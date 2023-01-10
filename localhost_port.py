import _thread
import os
from _socket import timeout, SHUT_RDWR
from socket import socket, AF_INET, SOCK_STREAM
from socketserver import BaseRequestHandler, TCPServer
from time import sleep
from urllib.parse import urlparse

from pyngrok import ngrok, conf

from log import logger


class EchoHandler(BaseRequestHandler):
    def __init__(self, callback, *args, **keys):
        self.callback = callback
        BaseRequestHandler.__init__(self, *args, **keys)

    def handle(self):
        print(f"{self.client_address} connected!")
        while True:
            msg = self.request.recv(8192)
            if not msg:
                break
            self.request.send(msg)
            if msg == b"Hello":
                self.callback(msg)


class LocalHostPort:
    """本地端口实用程序
    """
    __port__: int
    __already_in_use__: bool = False

    __test_server__: TCPServer = None

    __allow_incoming__: bool = False
    __allow_outgoing__: bool = False

    @property
    def allow_incoming(self):
        """此端口是否允许传入流量"""
        return self.__allow_incoming__

    @property
    def allow_outgoing(self):
        """此端口是否允许传出流量"""
        return self.__allow_outgoing__

    @property
    def already_in_use(self):
        """此本地端口是否已经被占用"""
        return self.__already_in_use__

    def test(self):
        logger.info(f'测试本地端口 {self.__port__}')
        """测试此端口,返回一个字符串表示此端口的出入方向连通性

        仅允许传入数据: "i"

        允许传出传入数据: "io"

        在执行完测试后,用于测试的socket服务将会被终止
        """
        # 检测测试服务器是否开启
        if not self.__test_server__:
            logger.info("重新创建测试服务器")
            _thread.start_new_thread(self.__create_test_server__, ())

        # 创建到此端口的隧道
        conf.get_default().auth_token = "233TJDuRG2SBXuyMyiIXqBNvEwM_6LZrX2XhyWU4srFj5bGVs"
        conf.get_default().ngrok_path = "/usr/local/bin/ngrok"
        try:
            tunnel = ngrok.connect(self.__port__, "tcp")
            # 获取隧道链接
            logger.info(f"隧道链接: {tunnel.public_url}")
            url = urlparse(tunnel.public_url)
            test_client = socket(AF_INET, SOCK_STREAM)
            test_client.settimeout(30)
            try:
                test_client.connect((url.hostname, url.port))
                test_client.send(b'Hello')
                res = test_client.recv(8192)
                if res == b"Hello":  # 如果能从隧道获取数据,表示端口允许出方向的流量
                    self.__allow_outgoing__ = True
            except timeout:
                self.__allow_outgoing__ = False
            finally:
                test_client.close()
                self.__test_server__.server_close()
                self.__test_server__.shutdown()
        except:
            logger.error(f"无法获取到端口{self.__port__}的隧道链接")

    def __create_test_server__(self):
        try:
            def callback(msg):
                if msg == b"Hello":
                    self.__allow_incoming__ = True

            def handler_factory(cb):
                def createHandler(*args, **keys):
                    return EchoHandler(cb, *args, **keys)

                return createHandler

            self.__test_server__ = TCPServer(('', self.__port__), handler_factory(callback))
            self.__test_server__.serve_forever()
        except OSError as e:
            if e.args[1] == 'Address already in use':
                self.__already_in_use__ = True

    def __init__(self, port: int):
        """
        新建此类的实例会在本地主机创建一个socket服务并监听端口(host)

        :param port 端口号
        """
        self.__port__ = port

        _thread.start_new_thread(self.__create_test_server__, ())


if __name__ == '__main__':
    port = LocalHostPort(25)
    port.test()
    print(port.allow_incoming)
    print(port.allow_outgoing)
