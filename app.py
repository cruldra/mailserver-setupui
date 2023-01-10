import _thread
import json
import os
import traceback
from inspect import getmembers, isfunction

import docker
from docker.errors import NotFound
from flask import Flask, render_template, request, url_for, redirect, Response
from flask.json import htmlsafe_dumps
from redislite import Redis

import installer
import tools
from db import Database
from project_paths import TEMPLATES, ROOT, STATIC
from dns_manager.helper import get_dns_manager
from dns_manager.manager import DnsManager
from tools import my_ip

app = Flask(__name__)
app.template_folder = TEMPLATES
app.static_folder = STATIC
red = Redis(ROOT.joinpath("redis.db"))


@app.route("/")
def index():
    settings_manager = tools.SettingsManager()
    # 如果请求参数中明确指定的需要激活的步骤
    if "active" in request.args:
        settings_manager.set_current_step(request.args['active'])
        settings_manager.save()

    # 自动获取当前服务器的ip
    myip = my_ip()
    domain_and_ip_form = settings_manager.get_form("domainAndIp")
    if not domain_and_ip_form['ip'] or domain_and_ip_form['ip'] != myip:
        domain_and_ip_form['ip'] = myip
    for com in settings_manager.json['components']:
        com['logo'] = com['logo'] if com['logo'].startswith("/static") else url_for("static", filename=com['logo'])
    return render_template('index.html', settings=htmlsafe_dumps(settings_manager.json),
                           dns_managers=htmlsafe_dumps(DnsManager.to_json_array()),
                           databases=htmlsafe_dumps(Database.to_json_array()))


@app.route("/services")
def services():
    """跳转到服务管理控制台"""
    return render_template('services.html', services=htmlsafe_dumps(tools.SettingsManager().get_services()))


@app.route("/install")
def install():
    """跳转到安装页面"""
    _thread.start_new_thread(installer.install, ())
    return render_template('install.html')


@app.route('/install_progress')
def install_progress():
    """
    使用sse发送安装过程日志
    :return:
    """

    def format_sse(data, event=None) -> str:
        msg = f'data: {data.decode("utf-8") if isinstance(data, bytes) else str(data)}\n\n'
        if event is not None:
            msg = f'event: {event}\n{msg}'
        return msg

    def event_stream():
        pubsub = red.pubsub()
        pubsub.subscribe('installation_progress')
        for message in pubsub.listen():
            yield format_sse(message['data'], 'installation_progress')

    return Response(event_stream(),
                    mimetype="text/event-stream")


@app.route("/previous", methods=['POST'])
def previous_step():
    settings_manager = tools.SettingsManager()
    settings_manager.active_previous_step()
    settings_manager.save()
    return redirect(url_for("index"))


@app.route("/next", methods=['POST'])
def next_step():
    settings_json = json.loads(request.form['json'])
    settings_manager = tools.SettingsManager(doc=settings_json)
    try:
        if settings_manager.has_next_step():
            settings_manager.active_next_step()
            return redirect(url_for("index"))
        else:
            return redirect(url_for("install"))
    finally:
        settings_manager.save()


@app.route("/dns/detect")
def detect_dns_manager():
    try:
        return get_dns_manager(request.args.get("host")).code, 200
    except Exception as e:
        return DnsManager.OTHER.code, 200


@app.route("/todo", methods=['POST'])
def todo():
    try:
        task = request.json['task']
        component_name = request.json['component_name']
        if task['redirect']:
            res = {
                "code": 0,
                "data": url_for(task['endpoint'], **task['parameters'])
            }
        else:
            func = next(fun for fun in getmembers(tools, isfunction) if fun[0] == task['endpoint'])[1]
            res = {
                "code": 0,
                "data": func(task['parameters'])
            }

        settings_manager = tools.SettingsManager()
        settings_manager.component_task_completed(component_name, task)
        settings_manager.save()
        return res

    except Exception as e:
        traceback.print_exc()
        return {
            "code": 1,
            "msg": str(e)
        }


@app.route("/mail-server/accounts")
def manage_mail_accounts():
    settings_manager = tools.SettingsManager()
    set_mail_server_form = settings_manager.get_form('setMailServer')
    mail_server_config_dir = os.path.abspath(f"{__file__}/../../{set_mail_server_form['data_dir']}/config")
    mail_account_manager = tools.MailAccountManager(mail_server_config_dir)
    return render_template('mail_accounts.html',
                           accounts=htmlsafe_dumps(list(map(lambda s: {"username": s}, mail_account_manager.list()))))


@app.route("/mail-server/accounts", methods=['POST'])
def add_mail_account():
    """添加邮箱账户"""
    try:
        settings_manager = tools.SettingsManager()
        set_mail_server_form = settings_manager.get_form('setMailServer')
        domain_and_ip_form = settings_manager.get_form('domainAndIp')
        mail_server_config_dir = os.path.abspath(f"{__file__}/../../{set_mail_server_form['data_dir']}/config")
        mail_account_manager = tools.MailAccountManager(mail_server_config_dir)

        mail_account_username = request.form['username'] if "@" in request.form[
            'username'] else f"{request.form['username']}@{domain_and_ip_form['domain']}"

        mail_account_manager.add(mail_account_username, request.form['password'],
                                 is_administrator=request.form.get('is_administrator', False))
        if mail_account_username not in ",".join(mail_account_manager.list()):
            raise Exception("账户添加失败")
        return {
            "code": 0,
            "msg": '账户已添加'
        }
    except Exception as e:
        traceback.print_exc()
        return {
            "code": 1,
            "msg": str(e)
        }


@app.route("/mail-server/accounts/pwd/update", methods=['POST'])
def update_mail_account_pwd():
    """修改邮箱账户密码"""
    try:
        settings_manager = tools.SettingsManager()
        set_mail_server_form = settings_manager.get_form('setMailServer')
        mail_server_config_dir = os.path.abspath(f"{__file__}/../../{set_mail_server_form['data_dir']}/config")
        mail_account_manager = tools.MailAccountManager(mail_server_config_dir)
        mail_account_manager.update(request.form['username'], request.form['new_pwd'])
        return {
            "code": 0,
            "msg": '密码已修改'
        }
    except Exception as e:
        traceback.print_exc()
        return {
            "code": 1,
            "msg": str(e)
        }


@app.route("/mail-server/accounts/del", methods=['POST'])
def del_mail_account():
    """删除邮箱账户"""
    try:
        settings_manager = tools.SettingsManager()
        set_mail_server_form = settings_manager.get_form('setMailServer')
        mail_server_config_dir = os.path.abspath(f"{__file__}/../../{set_mail_server_form['data_dir']}/config")
        mail_account_manager = tools.MailAccountManager(mail_server_config_dir)
        mail_account_manager.delete(request.form['username'])
        return {
            "code": 0,
            "msg": '已删除'
        }
    except Exception as e:
        traceback.print_exc()
        return {
            "code": 1,
            "msg": str(e)
        }


@app.route("/all_service_up")
def all_service_up():
    try:
        settings_manager = tools.SettingsManager()
        client = docker.from_env()

        def del_container(service):
            try:
                container = client.containers.get(service['container_name'])
                container.remove()
            except NotFound:
                pass

        [del_container(service) for service in settings_manager.get_services()]
        services_file = os.path.abspath(f"{__file__}/../../docker-compose.yml")
        return {
            "code": 0,
            "data": os.system(f"docker-compose -f {services_file} up -d")
        }
    except Exception as e:
        return {
            "code": 1,
            "msg": str(e)
        }


@app.route("/all_service_down")
def all_service_down():
    try:
        services_file = os.path.abspath(f"{__file__}/../../docker-compose.yml")
        return {
            "code": 0,
            "data": os.system(f"docker-compose -f {services_file} down")
        }
    except Exception as e:
        return {
            "code": 1,
            "msg": str(e)
        }


if __name__ == '__main__':
    app.run(debug=True, port=5001, host="0.0.0.0")
