import json
import os
import re
import socket
from pathlib import Path

import docker
import httpx
import requests
import rich
import yaml
from docker.errors import NotFound
from redislite import Redis
from stringcase import snakecase, alphanumcase

from dns_manager.manager import DnsManager
from dns_manager.record import DnsRecord
from log import logger
from project_paths import ROOT


class MailAccountManager:
    __docker_mail_server_config_dir__: Path

    def __init__(self, config_dir: Path):
        self.__docker_mail_server_config_dir__ = config_dir
        self.cache = self.CacheManager()

    def list(self):
        """获取邮件账户列表"""
        container = None
        try:
            client = docker.from_env()
            container = client.containers.run(image='docker.io/mailserver/docker-mailserver', detach=True,
                                              volumes={
                                                  self.__docker_mail_server_config_dir__: {
                                                      'bind': f'/tmp/docker-mailserver',
                                                      'mode': 'rw'}},
                                              command=f"""setup email list""")
            container.wait()

            return re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', container.logs().decode("utf-8"))
        finally:
            if container:
                container.remove()

    def add(self, name, pwd, **kwargs):
        """添加邮箱账户

        :param name: 用户名
        :param pwd: 密码
        :param is_administrator: 是否是管理员
        """

        client = docker.from_env()
        container = None
        try:
            container = client.containers.run(image='docker.io/mailserver/docker-mailserver', detach=True,
                                              volumes={
                                                  self.__docker_mail_server_config_dir__: {
                                                      'bind': f'/tmp/docker-mailserver',
                                                      'mode': 'rw'}},
                                              command=f"""setup email add {name} {pwd}""")
            container.wait()
            logger.info(container.logs().decode('utf-8'))
            self.cache.save_or_update(name, pwd, kwargs.get('is_administrator', False))
        finally:
            if container:
                container.remove()

    def update(self, name, npwd, **kwargs):
        """修改账户密码

        :param name: 用户名
        :param npwd: 新密码
        :param is_administrator: 是否是管理员
        """

        client = docker.from_env()
        container = None
        try:
            container = client.containers.run(image='docker.io/mailserver/docker-mailserver', detach=True,
                                              volumes={
                                                  self.__docker_mail_server_config_dir__: {
                                                      'bind': f'/tmp/docker-mailserver',
                                                      'mode': 'rw'}},
                                              command=f"""setup email update {name} {npwd}""")
            container.wait()
            logger.info(container.logs().decode('utf-8'))
            self.cache.save_or_update(name, npwd, kwargs.get('is_administrator', False))
        finally:
            if container:
                container.remove()

    def delete(self, name):
        """删除邮箱账户

        :param name:账户名
        """

        client = docker.from_env()
        container = None
        try:
            container = client.containers.run(image='docker.io/mailserver/docker-mailserver', detach=True,
                                              volumes={
                                                  self.__docker_mail_server_config_dir__: {
                                                      'bind': f'/tmp/docker-mailserver',
                                                      'mode': 'rw'}},
                                              command=f"""setup email del {name}""")
            container.wait()
            logger.info(container.logs().decode('utf-8'))
            self.cache.delete(name)
        finally:
            if container:
                container.remove()

    class CacheManager:
        def __init__(self, **kwargs):
            self.__redis__ = Redis("./redis.db")
            self.__key__ = kwargs.get('key', 'mail_accounts')

        def list(self):
            values = self.__redis__.hvals(self.__key__)
            return list(map(lambda s: json.loads(s), values)) if values else []

        def save_or_update(self, name, pwd, is_administrator):
            self.__redis__.hset(self.__key__, name, json.dumps({
                "name": name,
                "pwd": pwd,
                "is_administrator": is_administrator
            }))

        def delete(self, name):
            self.__redis__.hdel(self.__key__, name)


class SettingsManager:
    """
    设置管理器
    """

    def __init__(self, **kwargs):
        self.json = None
        self.file = ROOT.joinpath(kwargs.get('file', 'settings.json'))
        if "doc" in kwargs:
            self.json = kwargs['doc']
        else:
            with open(self.file) as fs:
                self.json = json.load(fs)

    def component_task_completed(self, component_name, task):
        """指示组件的某个任务已完成

        如果任务是一次性的,则从组件任务中移除

        :param component_name: 组件名称
        :param task: 任务
        """
        if task['persistence'] == "once":
            self.get_component(component_name)['todo_list'].pop(task['name'], None)

    def get_active_step_index(self):
        """获取当前激活的步骤的索引"""
        return indices(self.json['steps']['value'],
                       lambda e: e['key'] == self.json['steps']['active'])[0]

    def active_previous_step(self):
        """激活上一个步骤"""
        self.json['steps']['active'] = self.json['steps']['value'][self.get_active_step_index() - 1]['key']

    def has_next_step(self):
        """判断文档是否可以进行下一步"""
        return self.get_active_step_index() + 1 < len(self.json['steps']['value'])

    def active_next_step(self):
        """激活下一个步骤"""
        self.json['steps']['active'] = self.json['steps']['value'][self.get_active_step_index() + 1]['key']

    def get_component(self, component_name):
        """获取组件

        :param component_name: 组件名称
        """
        return next(x for x in self.json['components'] if x['name'] == component_name)

    def get_form(self, form_name):
        """获取表单

        :param form_name: 表单名称
        :return: 表单json
        """
        return self.json['forms'][form_name]

    def get_current_step(self):
        """获取当前正在进行的步骤"""
        return self.json['steps']['active']

    def set_current_step(self, step):
        """设置当前步骤"""
        self.json['steps']['active'] = step

    def save(self):
        """保存设置"""
        write_content_to_file(self.file, json.dumps(self.json, indent=4, sort_keys=True))

    def add_task_to_component(self, component_name, task):
        """添加todo任务到组件

        在所有任务全部添加完毕后,记得调用save()保存

        :param component_name: 组件名称
        :param task: 任务
        :return:
        """
        component = self.get_component(component_name)
        if "todo_list" not in component:
            component['todo_list'] = {}

        # 名字重复且参数是一个列表的情况下,直接追加参数而不是新建任务
        if task['name'] in component['todo_list'] and isinstance(task['parameters'], list):
            for p in task['parameters']:
                if not any((lambda p1: p1 == p)(p1) for p1 in component['todo_list'][task['name']]['parameters']):
                    component['todo_list'][task['name']]['parameters'] += [p]
        else:
            component['todo_list'][task['name']] = task

    def get_services(self):
        """获取服务列表"""
        p = ROOT.joinpath("docker-compose.yml")
        docker_compose_yml = yaml.safe_load(p.read_text())

        def get_container_name(component_name):
            """获取组件的docker容器名称

            查找顺序:component_obj>sub_step>lower(component_name)
            """
            component = self.get_component(component_name)
            default = snakecase(alphanumcase(component_name))
            if "container_name" in component:
                return component['container_name']
            elif "sub_step" in component:
                sub_step = self.json['forms'][component['sub_step']['key']]
                if "container_name" in sub_step:
                    return sub_step['container_name']
                else:
                    return default
            else:
                return default

        def get_status(container_name):
            client = docker.from_env()
            installed = any(
                (lambda key: docker_compose_yml['services'][key]['container_name'] == container_name)(key) for key in
                docker_compose_yml['services'])
            try:
                running = False if not installed else client.containers.get(container_name).status == "running"
            except NotFound:
                running = False
            label = None
            if not installed and not running:
                label = "未安装"
            elif installed and not running:
                label = "未启动"
            elif installed and running:
                label = "运行中"
            return {
                "installed": installed,
                "running": running,
                "label": label
            }

        def component_mapper(component):
            component_name = component['name']
            container_name = get_container_name(component_name)
            return {
                "name": component_name,
                "todo_list": component.get('todo_list', {}),
                "manage_url": component.get('manage_url', ''),
                "container_name": container_name,
                "status": get_status(container_name)
            }

        services = list(map(component_mapper, self.json['components']))
        service_names = list(map(lambda it: it['container_name'], services))
        for key in docker_compose_yml['services']:
            container_name = docker_compose_yml['services'][key]['container_name']
            if container_name not in service_names:
                services.extend([{
                    "name": key,
                    "container_name": container_name,
                    "status": get_status(container_name)
                }])
        return services


class PhplistConfiguration:
    def __init__(self, file):
        self.file = file
        self.__var_pattern__ = re.compile(
            r"""(^|;)\s*\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*=\s*('?|"?)(.*)\3\s*;""")
        self.__vals_pattern__ = re.compile(r"""\bdefine\(\s*('|")(.*)\1\s*,\s*('?|"?)(.*)\3\)\s*;""")
        self.__vars__ = {}
        self.__vals__ = {}
        with open(self.file) as file:
            self.__file_lines__ = file.readlines()
            for i, line in enumerate(self.__file_lines__):
                for match in self.__var_pattern__.finditer(line):
                    self.__vars__[match.group(2)] = i + 1, match.group(4)
                for match in self.__vals_pattern__.finditer(line):
                    self.__vals__[match.group(2)] = i + 1, match.group(4)

    # def write(self):
    #     vars = os.linesep.join(list(map(lambda key: f"${key} = '{self.__vars__[key][1]}';", self.__vars__.keys())))
    #     vals = os.linesep.join(list(map(lambda key: f"${key} = '{self.__vals__[key][1]}';", self.__vals__.keys())))
    #     print(vars + vals)

    def __writ__(self):
        Path(self.file).write_text(os.linesep.join(list(map(lambda l: l.strip(), self.__file_lines__))))

    def var(self, name: str, value: str = None):
        """获取或设置变量,php中变量格式为 $name=value"""
        if not value:
            return self.__vars__.get(name, '')[1]
        else:
            self.__vars__[name] = self.__vars__.get(name, '')[0], value
            self.__file_lines__[self.__vars__.get(name, '')[0] - 1] = f"${name} = '{value}';"
            self.__writ__()

    def val(self, name: str, value: str = None):
        """获取或设置常量,php中常量格式为 define("name",value);"""
        if not value:
            return self.__vals__.get(name, '')[1]
        else:
            self.__vals__[name] = self.__vals__.get(name, '')[0], value
            self.__file_lines__[self.__vals__.get(name, '')[0] - 1] = f'define("{name}","{value}");'
            self.__writ__()


def dns_check(params):
    """检查dns记录是否正确

    :param params: 待检查的记录列表,[{name, ak,sk}, records...]
    """
    dns_manager = DnsManager.code_of(params[0]['name'])
    dns_manager.init(params[0]['ak'], params[0]['sk'])
    msg = ""
    # dns_manager.check_record()
    for record in params[1: len(params)]:
        if not isinstance(record, DnsRecord):
            record = DnsRecord.from_dict(record)
        if not dns_manager.check_record(record):
            msg += f"记录[{str(record)}{os.linesep}]不存在或不正确"
    return "所有记录已正确配置" if not msg else msg


def my_ip():
    response = requests.request("GET", "https://api.ipify.org/")
    return response.text


def read_file_content(path):
    path = Path(path)
    path.name
    return Path(path).read_text()


def write_content_to_file(path, text):
    Path(path).write_text(text)


def indices(arr, predicate=lambda x: bool(x)):
    return [i for i, x in enumerate(arr) if predicate(x)]


def download_file(url, dist):
    with open(dist, "w") as download_file:
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


def check_remote_port_opened(host, port) -> bool:
    """
    检查远程主机上的某个端口是否处于监听状态
    :param host: 主机地址
    :param port: 端口号
    :return:
    """
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location = (host, port)
    result_of_check = a_socket.connect_ex(location)
    res = result_of_check == 0
    a_socket.close()
    return res
