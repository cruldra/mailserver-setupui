import os
import random
import re
import stat
from pathlib import Path
from shutil import copyfile

import docker
import yaml
from dns.rdatatype import RdataType
from docker.errors import ContainerError
from dotenv import load_dotenv, set_key
from redislite import Redis

import tools
from log import SSEHandler, formatter, logger
from project_paths import ROOT
from dns_manager.manager import DnsManager
from dns_manager.record import DnsRecord
from tools import download_file

# region 日志设置
red = Redis(ROOT.joinpath("redis.db"))
sse_handler = SSEHandler(red, "installation_progress")
sse_handler.setFormatter(formatter)
logger.addHandler(sse_handler)

# endregion 日志设置
docker_compose_file_path = ROOT.joinpath("docker-compose.yml")
home_path, config_dir_path = None, None


def __init_docker_compose_file__():
    """
    初始化docker-compose.yml文件
    :return: yaml文档对象
    """
    if not docker_compose_file_path.exists():
        docker_compose_file_path.write_text(
            yaml.dump({"version": "3.7", "networks": {"network": None}, "services": {}}))
    return yaml.safe_load(docker_compose_file_path.read_text())


def install():
    docker_compose_file_contents = __init_docker_compose_file__()
    settings_manager = tools.SettingsManager()

    def component_setup(component_name, installer, service_name):
        """根据settings.json中的设定添加或删除组件

        :param component_name: 组件名称
        :param installer: 安装器
        :param service_name: docker服务名称
        """
        if settings_manager.get_component(component_name)['checked']:
            installer(settings_manager, docker_compose_file_contents)
        else:
            docker_compose_file_contents['services'].pop(service_name, None)

    component_setup("Docker Mail Server", __install_mail_server__, "mailserver")
    component_setup("phpList", __install_phplist__, "phplist")
    component_setup("Database", __install_db__, "db")
    docker_compose_file_path.write_text(yaml.dump(docker_compose_file_contents))
    logger.info("all_done")


def __install_phplist__(settings_manager: tools.SettingsManager, docker_compose_doc):
    # 将phplist服务描述写入docker-compose.yml
    logger.info("生成phplist服务描述文件")
    set_phplist_form = settings_manager.get_form('setPhplist')
    docker_compose_doc['services']['phplist'] = {
        "image": "dongjak/phplist:3.6.6",
        "container_name": set_phplist_form.get('container_name', 'phplist'),
        "ports": [f"{set_phplist_form.get('port', '1231')}:80"],
        "volumes": [f"{set_phplist_form.get('php_ini', './config/php/php.ini')}:/usr/local/etc/php/php.ini",
                    f"{set_phplist_form.get('phplist_config_file', './config/phplist/config.php')}:/var/www/html/config/config.php",
                    "./config/phplist/config_extended.php:/var/www/html/config/config_extended.php",
                    "./.logs/apache:/var/log/httpd",
                    "./.logs/php:/var/log/php"],
        "restart": "always",
        "networks": ["network"],
        "environment": ['TZ=Asia/Shanghai'],
    }

    logger.info("phplist数据库配置")
    path = os.path.abspath(
        f"{__file__}/../../{set_phplist_form.get('phplist_config_file', './config/phplist/config.php')}")
    configuration = tools.PhplistConfiguration(path)
    if set_phplist_form['db_type'] == 'external':
        configuration.var("database_host", set_phplist_form['database_host'])
        configuration.var("database_name", set_phplist_form['database_name'])
        configuration.var("database_port", set_phplist_form['database_port'])
        configuration.var("database_user", set_phplist_form['database_user'])
        configuration.var("database_password", set_phplist_form['database_password'])
    else:
        set_database_form = settings_manager.get_form('setDatabase')
        configuration.var("database_host", 'db')
        configuration.var("database_name", set_database_form['init_db_name'])
        configuration.var("database_port", set_database_form['port'])
        configuration.var("database_user", set_database_form['username'])
        configuration.var("database_password", set_database_form['password'])

    logger.info("phplist smtp配置")
    domain_and_ip_form = settings_manager.get_form('domainAndIp')
    configuration.val("PHPMAILERHOST", f"mail.{domain_and_ip_form['domain']}")
    configuration.val("PHPMAILERPORT", "25")
    configuration.val("PHPMAILER_SECURE", "tls")

    administrator_mail_account = next(
        x for x in tools.MailAccountManager.CacheManager().list() if x['is_administrator'])
    configuration.var("phpmailer_smtpuser", administrator_mail_account['name'])
    configuration.var("phpmailer_smtppassword", administrator_mail_account['pwd'])

    # 如果phplist使用docker版的数据库,则需要将数据库容器和phplist容器连接到同一网络
    if settings_manager.get_component("Database")['checked'] and set_phplist_form['db_type'] == 'docker':
        docker_compose_doc['services']['phplist']['depends_on'] = ['db']
        docker_compose_doc['services']['phplist']['links'] = ['db']

    phplist_component = settings_manager.get_component('phpList')
    phplist_component['manage_url'] = f"http://{domain_and_ip_form['ip']}:{set_phplist_form.get('port', '1231')}/admin"
    settings_manager.save()
    logger.info("Phplist 安装完成")


def __install_db__(settings_manager, docker_compose_doc):
    set_database_form = settings_manager.get_form('setDatabase')
    logger.info("生成db服务描述文件")
    db_configs = {
        "mysql": {
            "username": "root",
            "init_db": "MYSQL_DATABASE",
            "password": "MYSQL_ROOT_PASSWORD",
            "data_dir": "/var/lib/mysql",
            "conf_files": ["./config/db/mysql/my.conf:/etc/mysql/conf.d/my.cnf"]
        },
        "postgresql": {
            "username": "postgres",
            "init_db": "POSTGRES_DB",
            "password": "POSTGRES_PASSWORD",
            "data_dir": "/var/lib/postgresql/data",
            "conf_files": ["./config/db/postgresql/postgresql.conf:/var/lib/postgresql/data/postgresql.conf",
                           "./config/db/postgresql/pg_hba.conf:/var/lib/postgresql/data/pg_hba.conf"],
        }
    }

    db_type = set_database_form.get('db_type', 'mysql')
    docker_compose_doc['services']['db'] = {
        "image": f"{db_type}:{set_database_form.get('version', '5.5.62')}",
        "container_name": set_database_form.get('container_name', 'db'),
        "expose": [f"{set_database_form.get('port', '3306')}"],
        "volumes": [f"./.db-data:{db_configs[db_type]['data_dir']}"] + db_configs[db_type]['conf_files'],
        "restart": "always",
        "networks": ["network"],
        "environment": ['TZ=Asia/Shanghai', f"{db_configs[db_type]['password']}={set_database_form['password']}",
                        f"{db_configs[db_type]['init_db']}={set_database_form['init_db_name']}"],
    }
    if db_type == "mysql" and set_database_form.get('install_php_myadmin', False):
        logger.info("生成phpmyadmin服务描述文件")
        docker_compose_doc['services']['phpmyadmin'] = {
            "image": 'phpmyadmin/phpmyadmin',
            "container_name": 'phplist_db_admin',
            "ports": ['8081:80'],
            "restart": "always",
            "networks": ["network"],
            "environment": ['PMA_HOST=db'],
            "depends_on": ['db'],
            "links": ['db']
        }
        database_component = settings_manager.get_component('Database')
        domain_and_ip_form = settings_manager.get_form('domainAndIp')
        database_component['manage_url'] = f"http://{domain_and_ip_form['ip']}:8081"
        settings_manager.save()
    logger.info("数据库服务 安装完成")


def __install_mail_server__(settings_manager: tools.SettingsManager, docker_compose_doc):
    """安装docker mail server

    :param settings_manager: 设置管理器
    :param docker_compose_doc: docker-compose.yml 文档对象
    """
    settings = settings_manager.json
    domain_and_ip_form = settings['forms']['domainAndIp']
    dns_manager = DnsManager.code_of(domain_and_ip_form['dnsManager'])
    dns_manager.init(ak=domain_and_ip_form['ak'], sk=domain_and_ip_form['sk'])
    domain = domain_and_ip_form['domain']
    ip = domain_and_ip_form['ip']

    set_mail_server_form = settings['forms']['setMailServer']
    docker_container_name = set_mail_server_form['container_name']
    docker_container_dns = set_mail_server_form['dns']
    global home_path, config_dir_path
    home_path = Path(set_mail_server_form['home_path'])
    config_dir_path = home_path.joinpath("config")
    # region 添加dns记录
    logger.info("添加dns记录")

    def add_record_if_not_existed(record: DnsRecord):
        """
        检查dns记录是否存在,如果不存在则添加
        :param record: dns记录
        :return: None
        """
        if dns_manager.check_record(record):
            logger.info(f"记录{record}已存在")
        else:
            dns_manager.addRecord(record, True)

    r1 = DnsRecord(domain=domain, name='mail', rdatatype=RdataType.A,
                   value=ip)
    r2 = DnsRecord(domain=domain, name='_dmarc', rdatatype=RdataType.TXT,
                   value=f"v=DMARC1; p=quarantine; rua=mailto:dmarc.report@{domain}; ruf=mailto:dmarc.report@{domain}; fo=0; adkim=r; aspf=r; pct=100; rf=afrf; ri=86400; sp=quarantine")
    r3 = DnsRecord(domain=domain, name='@', rdatatype=RdataType.TXT,
                   value="v=spf1 mx ~all")
    r4 = DnsRecord(domain=domain, name='@', rdatatype=RdataType.MX,
                   value=f"mail.{domain}")
    add_record_if_not_existed(r1)
    add_record_if_not_existed(r2)
    add_record_if_not_existed(r3)
    add_record_if_not_existed(r4)

    # 添加dns检查任务到to_do_list
    logger.info("创建dns检查任务")
    settings_manager.add_task_to_component('Docker Mail Server', {
        "name": "check_dns_records",
        "color": random.choice(["primary", "success", "info", "warning", "danger"]),
        "label": "检查dns解析",
        "persistence": "once",
        "endpoint": 'dns_check',
        "redirect": False,
        "parameters": [
            {"name": domain_and_ip_form['dnsManager'], "ak": domain_and_ip_form['ak'], "sk": domain_and_ip_form['sk']},
            r1.to_json(), r2.to_json(), r3.to_json(),
            r4.to_json()]
    })
    # endregion

    # region 申请证书
    logger.info("正在申请证书")

    def check_cert_exist():
        """检查对应域名的证书是否存在,不存在才会使用cert申请"""
        return config_dir_path.joinpath("certs/{domain}/fullchain1.pem").exists() and config_dir_path.joinpath(
            "certs/{domain}/privkey1.pem").exists()

    if not check_cert_exist():
        if dns_manager == DnsManager.NAMESILO:
            msg= f"namesilo不支持申请证书,你需要手动为域名{domain}申请泛域名证书并放到{config_dir_path.joinpath('certs/')}目录下"
            logger.info(msg)
            raise Exception(msg)
        else:
            try:
                cloudflare_ini_path = config_dir_path.joinpath("cloudflare.ini")
                cloudflare_ini_path.write_text(f"dns_cloudflare_api_token = {domain_and_ip_form['sk']}")
                client = docker.from_env()
                logs = client.containers.run(image='certbot/dns-cloudflare', detach=False, auto_remove=True, tty=True,
                                             stdin_open=True,
                                             name="certbot", volumes={
                        config_dir_path.joinpath("certs/"): {'bind': f'/etc/letsencrypt/archive', 'mode': 'rw'},
                        cloudflare_ini_path: {'bind': '/cloudflare.ini', 'mode': 'ro'}},
                                             command=f"""certonly  --noninteractive \
                                                              --agree-tos -m root@{domain} --preferred-challenges dns --expand  --dns-cloudflare  --dns-cloudflare-credentials /cloudflare.ini  \
                                                              -d *.{domain}  --server https://acme-v02.api.letsencrypt.org/directory""")
                logger.info(logs.decode("utf-8"))
            except ContainerError as e:
                logger.error(f"申请证书时出现异常:{str(e)}")
    else:
        logger.info("证书申请成功")
    # endregion

    # region 下载辅助脚本及添加执行权限
    logger.info("下载辅助脚本")
    man_script_path = home_path.joinpath("msman.sh")
    # 如果不存在就从远程下载
    if not man_script_path.exists():
        download_file("https://raw.githubusercontent.com/docker-mailserver/docker-mailserver/master/setup.sh",
                      man_script_path)
        st = os.stat(man_script_path)
        os.chmod(man_script_path, st.st_mode | stat.S_IEXEC)

    symbol_link = "/usr/local/bin/msman"
    if not Path(symbol_link).exists():
        os.symlink(man_script_path, symbol_link)
    logger.info(f"辅助脚本已下载,使用 msman help 获取更多帮助信息.")
    # endregion

    # region 修改mailserver.env
    logger.info("配置环境变量")
    example_env_file_path = home_path.joinpath("mailserver-example.env")
    env_file_path = home_path.joinpath("ms.env")
    copyfile(example_env_file_path, env_file_path)
    load_dotenv(env_file_path)
    set_key(env_file_path, "TZ", "Asia/Shanghai", 'never')
    set_key(env_file_path, "POSTMASTER_ADDRESS", f"root@{domain}", 'never')
    set_key(env_file_path, "PERMIT_DOCKER", "network", 'never')
    set_key(env_file_path, "SSL_TYPE", "manual", 'never')
    set_key(env_file_path, "SSL_CERT_PATH", "/tmp/ssl/fullchain1.pem", 'never')
    set_key(env_file_path, "SSL_KEY_PATH", "/tmp/ssl/privkey1.pem", 'never')
    logger.info("环境变量配置完成")
    # endregion

    # region 创建管理员账户
    logger.info("创建管理员账户")
    client = docker.from_env()

    mail_server_data_dir = home_path.joinpath(".mailserver-data")
    mail_server_config_dir = mail_server_data_dir.joinpath(".mailserver-data/config")
    # mail_account_manager = tools.MailAccountManager(mail_server_config_dir)
    # mail_account_manager.add(f"root@{domain}", "123394", is_administrator=True)
    # 添加管理邮箱账户到to_do_list
    settings_manager.add_task_to_component('Docker Mail Server', {
        "name": "manage_mail_accounts",
        "color": random.choice(["primary", "success", "info", "warning", "danger"]),
        "label": "管理邮箱账户",
        "persistence": "every",
        "endpoint": 'manage_mail_accounts',
        "redirect": True,
        "parameters": {}
    })
    # endregion

    # region 配置dkim
    logger.info("配置dkim")
    try:
        logs = client.containers.run(image='docker.io/mailserver/docker-mailserver', detach=False, auto_remove=True,
                                     tty=False,
                                     stdin_open=False,
                                     volumes={mail_server_config_dir: {'bind': f'/tmp/docker-mailserver',
                                                                       'mode': 'rw'}},
                                     command=f"""setup config dkim keysize 1024""")
        pattern = re.compile(r'\"(.*)\"')
        key_file_path = Path(
            os.path.abspath(f"{mail_server_config_dir}/opendkim/keys/{domain}/mail.txt"))
        res = pattern.findall(key_file_path.read_text())
        r5 = DnsRecord(domain=domain, name='mail._domainkey', rdatatype=RdataType.TXT,
                       value=f'{"".join(res)}')
        dns_manager.addRecord(r5, True)
        logger.info(logs.decode("utf-8"))
        settings_manager.add_task_to_component('Docker Mail Server', {
            "name": "check_dns_records",
            "label": "检查dns解析",
            "persistence": "once",
            "endpoint": 'dns_check',
            "parameters": [r5.to_json()]
        })
    except ContainerError as e:
        logger.error(f"配置dkim时出现异常 {str(e)}")
    # endregion

    # 保存任务设置
    settings_manager.save()

    # 将docker mail server服务描述写入docker-compose.yml
    logger.info("生成服务描述文件")
    docker_compose_doc['services']['mailserver'] = {
        "image": "docker.io/mailserver/docker-mailserver:latest",
        "container_name": docker_container_name if docker_container_name else "mailserver",
        "dns": docker_container_dns if docker_container_dns else "1.1.1.1",
        "hostname": "mail",
        "domainname": domain,
        "env_file": "ms.env",
        "ports": ["25:25", "143:143", "465:465", "587:587", "993:993"],
        "volumes": [f"{mail_server_data_dir}/mail-data/:/var/mail/",
                    f"{mail_server_data_dir}/mail-state/:/var/mail-state/",
                    f"{mail_server_data_dir}/mail-logs/:/var/log/mail/",
                    f"{mail_server_data_dir}/config/:/tmp/docker-mailserver/",
                    f"/etc/localtime:/etc/localtime:ro",
                    f"./config/certs/{domain}/:/tmp/ssl/:ro"],
        "restart": "always",
        "stop_grace_period": "1m",
        "cap_add": ["NET_ADMIN", "SYS_PTRACE"]
    }
    logger.info("Docker Mail Server安装完成")
