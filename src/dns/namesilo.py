import io
from typing import TypeVar
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import jsonpickle as jsonpickle
from dns.rdatatype import RdataType
from uplink import *

from src.dns.record import DnsRecord, Domain


class NamesiloApiClientException(Exception):
    """
    这个自定义异常表示一个namesilo api 客户端错误
    """

    # 构造函数包含message和cause两个参数

    # 一个静态示例,表示一个未知错误
    @staticmethod
    def unknown_error(cause: Exception = None):
        return NamesiloApiClientException("unknown error", cause)

    # 一个静态示例,表示一个http错误
    @staticmethod
    def http_error(cause: Exception = None):
        return NamesiloApiClientException("http error", cause)

    def __init__(self, message: str, cause: Exception = None):
        self.message = message
        self.cause = cause

    def __str__(self):
        return self.message


T = TypeVar('T')


class NamesiloApiResponse(object):

    def __init__(self, success: bool, msg: str, data: T) -> None:
        self.success = success
        self.msg = msg
        self.data: T = data


# def namesilo_api_response(cls):
#     for name, method in inspect.getmembers(cls, inspect.isfunction):
#         def wrapper(*args, **kwargs):
#             result = method(*args, **kwargs)
#             tree = ElementTree.parse(io.StringIO(result))
#             root = tree.getroot()
#             detail_node = root.find('reply').find("detail")
#             return NamesiloApiResponse(detail_node.text == 'success',
#                                        detail_node.text, result)
#
#         # 将包装函数赋值给原来的方法名
#         setattr(cls, name, wrapper)
#     return cls

def namesilo_base_response(response) -> NamesiloApiResponse:
    """
    如果是一个成功的http响应则原路返回,否则抛出一个NamesiloApiClientException异常
    """
    if 200 <= response.status_code < 300:
        tree = ElementTree.parse(io.StringIO(response.content.decode()))
        root = tree.getroot()
        detail_node = root.find('reply').find("detail")
        return NamesiloApiResponse(detail_node.text == 'success',
                                   detail_node.text, root)
    else:
        raise NamesiloApiClientException.http_error()


@response_handler
def getDnsRecordsByDomainResponse(response) -> list:
    resp = namesilo_base_response(response)
    root: Element = resp.data

    def get_host_name(host_val):
        return ".".join(host_val.split(".")[-2:])

    def get_record_name(host_val):
        # 统计host_val包含的.的个数
        if host_val.count(".")==1:
            return "@"

        # 截取到host_val中倒数第二个.之前的字符串
        return host_val[:host_val.rfind(".", 0, host_val.rfind("."))]

    def get_dns_record(resource_record_node: Element):
        host_node = resource_record_node.find("host")
        return DnsRecord(
            domain=get_host_name(host_node.text),
            name=get_record_name(host_node.text),
            value=resource_record_node.find("value").text,
            rdatatype=RdataType.from_text(resource_record_node.find("type").text),
            ttl=resource_record_node.find("ttl").text,
            id=resource_record_node.find("record_id").text
        )

    return [get_dns_record(resource_record_node) for resource_record_node in
            root.find('reply').findall("resource_record")]


@response_handler
def listDomainsResponse(response) -> list:
    resp = namesilo_base_response(response)
    root: Element = resp.data
    return [Domain(domain_node.attrib['created'], domain_node.attrib['expires'], domain_node.text) for domain_node in
            root.find('reply').find("domains").findall("domain")]


class ResponseStatus:
    """
    表示一个namesilo api的响应状态
    """
    SUCCESS = ("success", 200)
    EXIST = ("exist", 201)
    FAIL = ("fail", 500)

    def __init__(self, title, code):
        self.title = title
        self.code = code

    def __str__(self):
        return jsonpickle.encode({
            "title": self.title,
            "code": self.code
        })


@response_handler
def genericResponse(response) -> ResponseStatus:
    """
    namesilo客户端通用处理响应程序,它返回一个ResponseStatus对象
    :param response: http响应
    :return: ResponseStatus对象
    """
    resp = namesilo_base_response(response)
    root: Element = resp.data
    if root.find('reply').find("detail").text == "success":
        return ResponseStatus.SUCCESS
    elif root.find('reply').find("detail").text == "already exists":
        return ResponseStatus.EXIST
    else:
        return ResponseStatus.FAIL


@response_handler
def addDnsRecordToDomainResponse(response) -> str:
    resp = namesilo_base_response(response)
    root: Element = resp.data
    msg = root.find('reply').find("detail").text
    if msg != "success":
        raise NamesiloApiClientException(msg)
    return root.find('reply').find("record_id").text


@timeout(60)
@params({"version": "1", "type": "xml"})
class NamesiloApiClient(Consumer):
    """
    namesilo api客户端
    """

    def __init__(self, base_url="", access_key: Query(name="key") = "", client=None, converters=(), auth=None, hooks=(),
                 **kwargs):
        super().__init__(base_url, client, converters, auth, hooks, **kwargs)
        self.access_key = access_key

    @listDomainsResponse
    @get("listDomains")
    @params({"withBid": "1", "pageSize": "10"})
    def listDomains(self, skipExpired: Query = 1) -> list:
        pass

    @getDnsRecordsByDomainResponse
    @get("dnsListRecords")
    def getDnsRecordsByDomain(self, domain: Query) -> list:
        """
        获取域名的dns记录列表
        :param domain: 域名
        :return: list[DNSRecord]
        """
        pass

    @addDnsRecordToDomainResponse
    @get("dnsAddRecord")
    def addDnsRecordToDomain(self, domain: Query, host: Query("rrhost"),
                             value: Query("rrvalue"),
                             record_type: Query("rrtype") = "A",
                             ttl: Query("rrttl") = 3603,
                             delete_existing: Query("rrdelete") = 1) -> str:
        """
        添加一条dns记录到域名
        :param delete_existing: 是否删除已存在的记录
        :param domain: 域名,比如baidu.com
        :param host: 主机地址,比如www
        :param value: 记录值,比如110.100.100.100
        :param ttl: 默认3603
        :param record_type: 记录类型,默认为A类型,即指向一个具体的ip地址

        :return: 如果添加成功返回这条记录的id,否则抛出一条NamesiloApiClientException异常
        """
        pass

    @genericResponse
    @get("dnsDeleteRecord")
    def deleteDnsRecordFromDomain(self, domain: Query, record_id: Query("rrid")) -> ResponseStatus:
        """
        删除一条dns记录
        :param domain: 域名
        :param record_id: 记录id
        :return: ResponseStatus对象
        """
        pass
