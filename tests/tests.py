import json
import logging
import os
import random
import re
import stat
import subprocess
import unittest
from functools import partial, partialmethod
from inspect import getmembers, isfunction
from pathlib import Path
from urllib.request import urlretrieve

import docker
import httpx as httpx
import pydnsbl
import rich
import yaml
from dns.rdatatype import RdataType
from docker import APIClient
from dotenv import load_dotenv, set_key
from flask import url_for
from redislite import Redis
from stringcase import snakecase, alphanumcase
from termcolor import colored

from src import tools
from dns.exceptions import DnsException
from dns.helper import get_dns_manager, get_name_server
from dns.manager import DnsManager
from dns.namesilo import NamesiloApiClient, ResponseStatus
from dns.record import DnsRecord
from tools import download_file


class LoggerTests(unittest.TestCase):
    def test_root_logger(self):
        logging.basicConfig(level=logging.INFO)
        logging.info("hello")

    def test_get_root_logger_handler(self):
        print(logging.getLogger("11").handlers)

    def test_custom_logging_level(self):
        logging.TRACE = 5
        logging.addLevelName(logging.TRACE, 'TRACE')
        logging.Logger.trace = partialmethod(logging.Logger.log, logging.TRACE)
        logging.trace = partial(logging.log, logging.TRACE)

        logging.basicConfig(level=logging.TRACE)
        logging.trace("hello")

    def test_simple_formatter(self):
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s : %(levelname)s : %(name)s : %(message)s %(pathname)s')
        logging.info("hello")


class ArrayStreamTests(unittest.TestCase):
    def test_foreach_lambda(self):
        # [(lambda x: print(x))(x) for x in range(10)]
        [(lambda x: print(x))(x) for x in range(10)]


class DictTests(unittest.TestCase):
    def test_eq(self):
        d1 = {
            "host": "9l2z.xyz",
            "name": "mail",
            "type": 1,
            "value": "103.47.113.84"
        }
        d2 = {
            "host": "9l2z.xyz",
            "name": "mail",
            "type": 1,
            "value": "103.47.113.84"
        }
        self.assertTrue(d1 == d2)

    def test_foreach(self):

        services = [{"container_name": "mailserver", "manage_url": "", "name": "Docker Mail Server",
                     "status": {"installed": True, "label": "未启动", "running": False}, "todo_list": {
                "check_dns_records": {"color": "warning", "endpoint": "dns_check", "label": "检查dns解析",
                                      "name": "check_dns_records", "parameters": [
                        {"ak": "", "name": "cloudflare", "sk": "ozTikFmlS9bxLmnJqLc80uCLCeBAQvcXOJ8mTVeW"},
                        {"host": "9l2z.xyz", "name": "mail", "type": 1, "value": "103.47.113.84"},
                        {"host": "9l2z.xyz", "name": "_dmarc", "type": 16,
                         "value": "v=DMARC1; p=quarantine; rua=mailto:dmarc.report@9l2z.xyz; ruf=mailto:dmarc.report@9l2z.xyz; fo=0; adkim=r; aspf=r; pct=100; rf=afrf; ri=86400; sp=quarantine"},
                        {"host": "9l2z.xyz", "name": "@", "type": 16, "value": "v=spf1 mx ~all"},
                        {"host": "9l2z.xyz", "name": "@", "type": 15, "value": "mail.9l2z.xyz"}], "persistence": "once",
                                      "redirect": False},
                "manage_mail_accounts": {"color": "danger", "endpoint": "manage_mail_accounts", "label": "管理邮箱账户",
                                         "name": "manage_mail_accounts", "parameters": {}, "persistence": "every",
                                         "redirect": True}}},
                    {"container_name": "phplist", "manage_url": "http://103.47.113.84:1231/admin", "name": "phpList",
                     "status": {"installed": True, "label": "未启动", "running": False}, "todo_list": {}},
                    {"container_name": "db", "manage_url": "http://103.47.113.84:8081", "name": "Database",
                     "status": {"installed": True, "label": "未启动", "running": False}, "todo_list": {}}]
        service_names = list(map(lambda it: it['container_name'], services))
        p = Path(os.path.abspath(__file__ + "/../../docker-compose-example.yml"))
        docker_compose_yml = yaml.safe_load(p.read_text())
        serviecs_dict = docker_compose_yml['services']
        for key in serviecs_dict:
            container_name = serviecs_dict[key]['container_name']

            if container_name not in service_names:
                services.extend([{
                    "name": key,
                    "container_name": container_name,
                    "status": ""
                }])

        container_name = "mailserver1"

        def predicate(key):
            return docker_compose_yml['services'][key]['container_name'] == container_name

        # for service in docker_compose_yml['services']:
        #     print(predicate(service))
        print(any(predicate(service) for service in docker_compose_yml['services']))
        # print(json.dumps(services, indent=4, sort_keys=True))


class MailAccountManagerTests(unittest.TestCase):
    def test_cache(self):
        cache_manager = tools.MailAccountManager.CacheManager()
        cache_manager.save_or_update("hasaiki@gmail.com", "123394", True)
        cache_manager.save_or_update("root@gmail.com", "123394", True)
        cache_manager.save_or_update("root@gmail.com", "123456", True)
        cache_manager.delete("hasaiki@gmail.com")
        print(cache_manager.list())

        # redis = Redis('./redis.db')
        # redis.hset("mail_accounts","hasaiki@gmial.com",json.dumps({
        #     "name": "hasaiki@gmail.com",
        #     "pwd": "123394",
        #     "is_administrator": True
        # }))


class RandomTests(unittest.TestCase):
    def test_random_choise(self):
        print(random.choice(["primary", "success", "info", "warning", "danger"]))

    def test(self):
        print(len(tools.MailAccountCacheManager.list()))
        next(x for x in tools.MailAccountCacheManager.list() if x['is_administrator'])


class PhplistConfigurationTests(unittest.TestCase):
    def test_get_var(self):
        configuration = tools.PhplistConfiguration(
            "/Users/liuye/DockerProjects/mail-marketing-docker/config/phplist/config.php")
        self.assertEqual(configuration.var("bounce_protocol"), 'pop')
        self.assertEqual(configuration.var("database_port"), '3306')

    def test_get_const(self):
        configuration = tools.PhplistConfiguration(
            "/Users/liuye/DockerProjects/mail-marketing-docker/config/phplist/config.php")
        self.assertEqual(configuration.val("PHPMAILER"), '1')

    def test_set_var(self):
        configuration = tools.PhplistConfiguration(
            "/Users/liuye/DockerProjects/mail-marketing-docker/config/phplist/config.php")
        configuration.var("database_host", 'db1')


class PhpSourceFilePaseTest(unittest.TestCase):
    def test_parse(self):
        define_pattern = re.compile(r"""\bdefine\(\s*('|")(.*)\1\s*,\s*('?|"?)(.*)\3\)\s*;""")
        assign_pattern = re.compile(
            r"""(^|;)\s*\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*=\s*('?|"?)(.*)\3\s*;""")

        # php_vars = {}
        php_vals = {}
        for line in open("/Users/liuye/DockerProjects/mail-marketing-docker/config/phplist/config.php"):
            for match in define_pattern.finditer(line):
                php_vals[match.group(2)] = match.group(4)
            # for match in assign_pattern.finditer(line):
            #     php_vars[match.group(2)] = match.group(4)
        print(json.dumps(php_vals))

    def test_parse_var(self):
        p = re.compile(r"""(^|;)\s*\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*=\s*('|")(.*)\3\s*;""")
        with open('/Users/liuye/DockerProjects/mail-marketing-docker/config/phplist/config.php', 'r') as file:
            for line in file.readlines():
                res = p.match(line)
                print(res)


class DockerClientTests(unittest.TestCase):
    def test_run_container_and_return_log(self):
        client = docker.from_env()
        container = client.containers.run('ubuntu:latest', detach=True, command=f'echo 12121')
        print(container.wait())
        print(container.logs())
        container.remove()
        # re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', logs.decode("utf-8"))


class MunchTests(unittest.TestCase):
    def test_dict_obj(self):
        # print(DefaultMunch.fromDict({"host": '11'}).host)
        dic = {
            "host": "9l2z.xyz",
            "name": "_dmarc",
            "type": 16,
            "value": "v=DMARC1; p=quarantine; rua=mailto:dmarc.report@9l2z.xyz; ruf=mailto:dmarc.report@9l2z.xyz; fo=0; adkim=r; aspf=r; pct=100; rf=afrf; ri=86400; sp=quarantine"
        }
        self.assertFalse(isinstance(dic, DnsRecord))
        self.assertEqual(dic.get("safa"), None)
        self.assertTrue(isinstance(DnsRecord.from_dict(dic), DnsRecord))


class ExceptionTests(unittest.TestCase):
    def test_raise_exception(self):
        raise DnsException("111")


class ReflectionTests(unittest.TestCase):
    def test_dir(self):
        for fun in dir(tools):
            print(fun)
        print(tools)

    def test_get_endpoint_urls(self):
        # for fun in getmembers(app, isfunction):
        #     print(fun[0])
        print(url_for("index"))

    def test_getmembers(self):
        func = next(fun for fun in getmembers(tools, isfunction) if fun[0] == "my_ip")[1]
        print(func())


class JsonTests(unittest.TestCase):
    def test_serialize_tunple(self):
        print(json.dumps((True, "asdfa")))

    def test_get_dict_key(self):
        dict = {}
        # print(dict['todo_list']) # KeyError: 'todo_list'
        print(dict.get("todo_list", "1"))

    def test_serialize(self):
        print(json.dumps(DnsRecord(host="domain", name='mail', rdatatype=RdataType.A,
                                   value="ip"), default=lambda obj: {
            "host": obj.host,
            "name": obj.name,
            "value": obj.value,
            "type": obj.rdatatype.name
        }))

    def test_dump(self):
        with open("/Users/liuye/Downloads/test.json") as f:
            settings = json.load(f)
        component = next(x for x in settings['components'] if x['name'] == 'Docker Mail Server')
        component['todo_list'] = [{
            "title": 'dns检查'
        }]
        Path("/Users/liuye/Downloads/test.json").write_text(json.dumps(settings))


class RegexTests(unittest.TestCase):
    def test_extract_emails(self):
        for e in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', """
        * root1@9l2z.xyz ( 1.0K / ~ ) [0%]
        * root2@9l2z.xyz ( 1.0K / ~ ) [0%]
        * root3@9l2z.xyz ( 1.0K / ~ ) [0%]
        """):
            print(e)
        print(type(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', """
        * root1@9l2z.xyz ( 1.0K / ~ ) [0%]
        * root2@9l2z.xyz ( 1.0K / ~ ) [0%]
        * root3@9l2z.xyz ( 1.0K / ~ ) [0%]
        """)))


class StringCaseTests(unittest.TestCase):
    def test_to_snake_case(self):
        self.assertEqual(snakecase(alphanumcase("Docker Mail Server")), "docker_mail_server")


class CallShellCommandTests(unittest.TestCase):
    def test_by_os(self):
        # print(os.system("""
        # cat  /Users/liuye/fsdownload/mail.txt
        # """))
        # print(os.system("which ngrok"))
        print(os.system("docker-compose -f "))

    def test_cat_mail_txt(self):
        pattern = re.compile(r'\"(.*)\"')
        res = pattern.findall(Path("/Users/liuye/fsdownload/mail.txt").read_text())

        print("".join(res))


class EnvFileTests(unittest.TestCase):
    def test_load_env(self):
        env_file_path = os.path.abspath(f"{__file__}/../../ms.env")
        load_dotenv(env_file_path)
        set_key(env_file_path, "TZ", "aaaa", 'never')
        print(os.getenv('TZ'))


class FileDownloadTests(unittest.TestCase):
    def test_download_file(self):
        man_script_path = os.path.abspath(__file__ + "/../../msman.sh")
        urlretrieve("https://raw.githubusercontent.com/docker-mailserver/docker-mailserver/master/setup.sh",
                    man_script_path)
        st = os.stat(man_script_path)
        os.chmod(man_script_path, st.st_mode | stat.S_IEXEC)
        os.symlink(man_script_path, "/usr/local/bin/msman")

    def test_download_by_httpx(self):
        with open("/Users/liuye/Downloads/test.sh", "w") as download_file:
            url = "https://raw.githubusercontent.com/docker-mailserver/docker-mailserver/master/setup.sh"
            with httpx.stream("GET", url) as response:
                total = int(response.headers["Content-Length"])
                with rich.progress.Progress(
                        "[progress.percentage]{task.percentage:>3.0f}%",
                        rich.progress.BarColumn(bar_width=None),
                        rich.progress.DownloadColumn(),
                        rich.progress.TransferSpeedColumn(),
                ) as progress:
                    download_task = progress.add_task("Download", total=total)
                    for chunk in response.iter_bytes():
                        download_file.write(chunk.decode('utf-8'))
                        progress.update(download_task, completed=response.num_bytes_downloaded)

    def test_download2(self):
        download_file("https://raw.githubusercontent.com/docker-mailserver/docker-mailserver/master/setup.sh",
                      "/Users/liuye/Downloads/test.sh")


class CertInstallTests(unittest.TestCase):
    def test_print_cmd(self):
        domain = "hasaiki.xyz"
        email = "cruldra@cruldra.cn"
        cf_token = "ozTikFmlS9bxLmnJqLc80uCLCeBAQvcXOJ8mTVeW"
        print(f"""echo "dns_cloudflare_api_token = {cf_token}" >> /cloudflare.ini certonly  --noninteractive \
                              --agree-tos -m {email} --preferred-challenges dns --expand  --dns-cloudflare  --dns-cloudflare-credentials /cloudflare.ini  \
                              -d *.{domain}  --server https://acme-v02.api.letsencrypt.org/directory""")

    def test_docker_low_level_api(self):
        client = APIClient(base_url='unix://var/run/docker.sock')
        client.logs()
        print(client)

    def test_cloudflare(self):
        domain = "9l2z.xyz"
        email = "cruldra@cruldra.cn"
        cf_token = "ozTikFmlS9bxLmnJqLc80uCLCeBAQvcXOJ8mTVeW"

        cloudflare_ini = Path(os.path.abspath(__file__ + "/../../config/cloudflare.ini"))
        cloudflare_ini.write_text(f"dns_cloudflare_api_token = {cf_token}")
        client = docker.from_env()
        container = client.containers.run(image='certbot/dns-cloudflare', detach=True, auto_remove=False, tty=True,
                                          stdin_open=True,
                                          name="certbot", volumes={
                os.path.abspath(__file__ + "/../../config/certs"): {'bind': f'/etc/letsencrypt/archive',
                                                                    'mode': 'rw'},
                cloudflare_ini: {'bind': '/cloudflare.ini', 'mode': 'ro'}},
                                          command=f"""certonly  --noninteractive \
                                                  --agree-tos -m {email} --preferred-challenges dns --expand  --dns-cloudflare  --dns-cloudflare-credentials /cloudflare.ini  \
                                                  -d *.{domain}  --server https://acme-v02.api.letsencrypt.org/directory""")
        print(container)
        # client = APIClient(base_url='unix://var/run/docker.sock')
        # generator = client.logs("certbot")
        # while True:
        #     output = generator.__next__
        #     print(output)
        # try:
        #     output = output.strip('\r\n')
        #     json_output = json.loads(output)
        #     if 'stream' in json_output:
        #         click.echo(json_output['stream'].strip('\n'))
        # except StopIteration:
        #     click.echo("Docker image build complete.")
        #     break
        # except ValueError:
        #     click.echo("Error parsing output from docker image build: %s" % output)
        # for log in container.logs():
        #     print(log)
        # with tempfile.NamedTemporaryFile(suffix='.ini', prefix="cloudflare", mode="w") as tf:
        #     tf.write("dns_cloudflare_api_token = {cf_token}")
        #     tf.flush()

    def test_run_docker_container(self):
        client = docker.from_env()
        container = client.containers.run(image='dongjak/layui-chinese-doc:latest', detach=False,
                                          name="layui-chinese-doc11")
        print(container)


class InstallerTests(unittest.TestCase):

    def test_ip_reputation(self):
        # url = "https://check.spamhaus.org/not_listed/?searchterm=234234124"
        #
        # payload = {}
        # headers = {
        #     'authority': 'check.spamhaus.org',
        #     'cache-control': 'max-age=0',
        #     'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
        #     'sec-ch-ua-mobile': '?0',
        #     'sec-ch-ua-platform': '"macOS"',
        #     'dnt': '1',
        #     'upgrade-insecure-requests': '1',
        #     'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
        #     'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        #     'sec-fetch-site': 'same-origin',
        #     'sec-fetch-mode': 'navigate',
        #     'sec-fetch-user': '?1',
        #     'sec-fetch-dest': 'document',
        #     'referer': 'https://check.spamhaus.org/?__cf_chl_jschl_tk__=HKPUvZk3PYSeyi.hqRqvP4wzGsLd_CHw6hhaPQ03BFE-1640871808-0-gaNycGzNCb0',
        #     'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
        #     'cookie': 'cb-enabled=enabled; _hjSessionUser_1643020=eyJpZCI6IjA2MjRkMGYyLTIxZmQtNTlmYy05YWJhLWEyZGE5ODA5MzMzZSIsImNyZWF0ZWQiOjE2NDA1ODcwMzMxMTcsImV4aXN0aW5nIjp0cnVlfQ==; cf_clearance=DMvxc0heQN6tfdFwwIpxmf4OoXzcOEjAkLr20prveQg-1640871811-0-150; PHPSESSID=qe7ceuo55a34jnbcq5ao49vmgm; _hjSession_1643020=eyJpZCI6IjFlOGQzODcyLTZjYWEtNDY0My1iZDJlLTVlMDgzZjk3ZDQ1NyIsImNyZWF0ZWQiOjE2NDA4NzE4MTQ4ODR9'
        # }
        # response = requests.request("GET", url, headers=headers, data=payload)
        # # print(response.text)
        # soup = BeautifulSoup(response.text)
        # print(soup.select(".page-header>h2")[0].text)
        ip_checker = pydnsbl.DNSBLIpChecker()
        # self.assertTrue(ip_checker.check('120.242.217.223').blacklisted) # 本机
        # print(ip_checker.check('194.5.78.236')) # 西伯利亚测试机
        # print(ip_checker.check('103.231.174.66'))# api
        print(ip_checker.check('106.13.64.61'))
        # self.assertFalse(ip_checker.check('194.5.78.236').blacklisted)


class YieldExpTestCase(unittest.TestCase):
    def testYield(self):
        def foo():
            print("starting...")
            while True:
                res = yield 4
                print("res:", res)

        g = foo()
        print(next(g))
        print("*" * 20)
        print(next(g))


class DomainTestCase(unittest.TestCase):
    def test_cloudflare_add_record(self):
        """测试使用cloudflare api添加解析记录"""
        domain = "9l2z.xyz"
        manager = get_dns_manager(domain)
        manager.init(sk="ozTikFmlS9bxLmnJqLc80uCLCeBAQvcXOJ8mTVeW")
        manager.addRecord(record=DnsRecord(host=domain, name='@', rdatatype=RdataType.MX,
                                           value=f"mail.{domain}"), unique=True)
        # manager.addRecord(
        #     record=DnsRecord(host=domain, name="test", value="120.12.13.14", rdatatype=RdataType.A))

    def test_get_name_server(self):
        nameservers = get_name_server("civetcat.net")
        self.assertEqual(nameservers[1], "porter.ns.cloudflare.com.")  # add assertion here
        self.assertEqual(get_dns_manager("civetcat.net"), DnsManager.CLOUDFLARE)

    def test_dns_manager_enum(self):
        # for e in DnsManager:
        #     print(e)
        values = DnsManager.to_json_array()
        print(json.dumps(values))
        self.assertEqual(DnsManager.NAMESILO.label, "Namesilo")

    def test_get_nameserver(self):
        process = subprocess.Popen(["dig", "+short", "ns", "civetcat.net"], stdout=subprocess.PIPE,
                                   universal_newlines=True)
        output = process.communicate()

        ip_arr = []
        for data in output:
            if 'Address' in data:
                ip_arr.append(data.replace('Address: ', ''))
        ip_arr.pop(0)

        print
        ip_arr
        self.assertEqual(1, 1)  # add assertion here


class RedisLiteTestCase(unittest.TestCase):
    def test_chinese_support(self):
        redis_connection = Redis('./redis.db')
        s = u"我草"
        s.encode('UTF-8')
        redis_connection.set("a", s)
        print(redis_connection.get("a").decode("UTF-8"))

    def test_redis_lite_pu_sub(self):
        redis_connection = Redis('./redis.db')
        redis_connection.publish('chat', '#########')
        redis_connection.publish('chat', '1')
        redis_connection.publish('chat', '2')
        redis_connection.publish('chat', '3')
        pubsub = redis_connection.pubsub()
        pubsub.subscribe('chat')
        for message in pubsub.listen():
            print(message)
            yield 'data: %s\n\n' % message['data']


class ConsoleColorTestCase(unittest.TestCase):
    def test_print_color(self):
        print(
            f"如果你正在{colored('Docker', 'green')}中运行{colored('setupui', 'green')},请使用链接{colored('http://your_host:5001', 'green')}")


class YamlTestCase(unittest.TestCase):
    def test_load_yaml(self):
        p = Path("/Users/liuye/DockerProjects/mail-marketing-docker/docker-compose-example.yml")
        doc = yaml.safe_load(p.read_text())
        print(yaml.dump(doc))


class DNSManagerTestCase(unittest.TestCase):
    def testListDomainsByCloudFlare(self):
        # dns_manager = DnsManager.code_of("CLOUDFLARE")
        # dns_manager.init(ak='ozTikFmlS9bxLmnJqLc80uCLCeBAQvcXOJ8mTVeW', sk='')
        # dns_manager.list()
        pass


# @namesilo_api_response
class TestClass:
    def testFun(self, name: str):
        return '''<?xml version="1.0"?>
<namesilo>
    <request>
        <operation>dnsListRecords</operation>
        <ip>103.251.113.133</ip>
    </request>
    <reply>
        <code>300</code>
        <detail>success</detail>
        <resource_record>
            <record_id>bcf301247ae4cd7aca0d628377c5a35b</record_id>
            <type>A</type>
            <host>note.cruldra.com</host>
            <value>103.251.113.133</value>
            <ttl>3603</ttl>
            <distance>0</distance>
        </resource_record>
        <resource_record>
            <record_id>af0912091a8b28dd46009969c339c92a</record_id>
            <type>A</type>
            <host>todo.cruldra.com</host>
            <value>103.251.113.133</value>
            <ttl>3603</ttl>
            <distance>0</distance>
        </resource_record>
        <resource_record>
            <record_id>c24caced286647e40ad1e463d416ae8a</record_id>
            <type>A</type>
            <host>v2ray.cruldra.com</host>
            <value>103.251.113.133</value>
            <ttl>3603</ttl>
            <distance>0</distance>
        </resource_record>
    </reply>
</namesilo>'''


class NamesiloApiTestCase(unittest.TestCase):
    apiClient = NamesiloApiClient(base_url="https://www.namesilo.com/api/", access_key="d629e564e617d775d10f15")

    def testListDomains(self):
        self.assertEqual(len(self.apiClient.listDomains("cruldra.com")), 4)

    def testListDnsRecord(self):
        self.assertTrue(isinstance(self.apiClient.getDnsRecordsByDomain("cruldra.com"), list))

    def testAddDnsRecordToDomain(self):
        self.assertIsInstance(self.apiClient.addDnsRecordToDomain("cruldra.com", "test", "192.168.1.1"), str)

    def testDeleteDnsRecordFromDomain(self):
        self.assertEqual(self.apiClient.deleteDnsRecordFromDomain("cruldra.com", "test"), ResponseStatus.FAIL)


if __name__ == '__main__':
    unittest.main()
