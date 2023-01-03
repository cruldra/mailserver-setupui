import io
from typing import TypeVar
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import jsonpickle as jsonpickle
from dns.rdatatype import RdataType
from uplink import *

from src.dns.record import DnsRecord


class NamesiloApiClientException(Exception):
    """
    这个自定义异常表示一个namesilo api 客户端错误
    """

    def __init__(self, response):
        super().__init__(response)
        self.response = response

    def __str__(self):
        return jsonpickle.encode({
            "msg": "请求异常",
            "code": self.response['code']
        })


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
        raise NamesiloApiClientException(response)


@response_handler
def dns_records_response(response) -> list:
    resp = namesilo_base_response(response)
    root: Element = resp.data

    def get_host_name(host_val):
        substr = host_val.split(".")[1:]  # 获取 "." 之后的子串
        result = ".".join(substr)  # 将子串用 "." 连接起来
        return result

    def get_record_name(host_val):
        return host_val.split(".")[0]

    def get_dns_record(resource_record_node: Element):
        host_node = resource_record_node.find("host")
        return DnsRecord(
            host=get_host_name(host_node.text),
            name=get_record_name(host_node.text),
            value=resource_record_node.find("value").text,
            rdatatype=RdataType.from_text(resource_record_node.find("type").text),
            ttl=resource_record_node.find("ttl").text,
            id=resource_record_node.find("record_id").text
        )

    return [get_dns_record(resource_record_node) for resource_record_node in
            root.find('reply').findall("resource_record")]


def dnsRecordsResponse(response): pass


@timeout(60)
@params({"version": "1", "type": "xml", "key": "d629e564e617d775d10f15"})
@response_handler(namesilo_base_response)
class NamesiloApiClient(Consumer):
    @dns_records_response
    @get("dnsListRecords")
    def getDnsRecordsByDomain(self, domain: Query) -> list: pass
