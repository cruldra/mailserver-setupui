from enum import Enum
from types import DynamicClassAttribute

import CloudFlare

from dns_manager.record import DnsRecord


class IDnsManager:
    __ak__: str
    __sk__: str

    @DynamicClassAttribute
    def ak(self):
        return self.__ak__

    @DynamicClassAttribute
    def sk(self):
        return self.__sk__

    def init(self, ak="", sk=""):
        self.__ak__ = ak
        self.__sk__ = sk

    def addRecord(self, record: DnsRecord, unique: bool = False):
        """添加记录

        :param  record: dns记录
        :param unique: 确保这条记录是唯一的
        """
        pass

    def listDnsRecords(self, domain, **kwargs):
        """获取dns记录列表

        :param domain: 域名
        """
        pass

    def deleteRecord(self, record_id: str):
        """删除记录
        record_id:记录id
        """
        pass

    def check_record(self, record: DnsRecord) -> bool:
        """
        检查dns记录是否存在

        :param record: 要检查的dns记录
        """
        pass


class DnsManager(IDnsManager, Enum):
    CLOUDFLARE = ("cloudflare", "Cloudflare", "cloudflare.com")
    ALIYUN = ("aliyun", "阿里云", "hichina.com")
    NAMESILO = ("namesilo", "Namesilo", "namesilo.com")
    OTHER = ("other", "其它", "other")
    _code_: str
    _label_: str
    _nameserver_pattern_: str

    def __get_cf_zone_id__(self, host):
        cf = CloudFlare.CloudFlare(email=self.ak, token=self.sk)
        zones = cf.zones.get(params={'name': host, 'per_page': 1})
        if len(zones) == 0:
            raise DnsException(f"请确认域名{host}成功交由{self.label}托管.")
        return zones[0]['id']

    def listDnsRecords(self, domain, **kwargs):
        def cloudflare():
            cf = CloudFlare.CloudFlare(email=self.ak, token=self.sk)
            return cf.zones.dns_records.get(self.__get_cf_zone_id__(domain))

        def namesilo():
            namesilo_client = NamesiloApiClient(base_url="https://www.namesilo.com/api/", access_key=self.ak)
            return namesilo_client.getDnsRecordsByDomain(domain)

        match self.code:
            case 'cloudflare':
                return cloudflare()
            case 'namesilo':
                return namesilo()
            case _:
                raise DnsException.UNSUPPORTED(self.code)

    def deleteRecord(self, record_id: str):
        def cloudflare():
            cf = CloudFlare.CloudFlare(email=self.ak, token=self.sk)
            return cf.zones.dns_records.delete(self.__get_cf_zone_id__(record_id), record_id)

        def namesilo():
            namesilo_client = NamesiloApiClient(base_url="https://www.namesilo.com/api/", access_key=self.ak)
            return namesilo_client.deleteDnsRecordFromDomain(record_id)

        match self.code:
            case 'cloudflare':
                return cloudflare()
            case 'namesilo':
                return namesilo()
            case _:
                raise DnsException.UNSUPPORTED(self.code)

    def addRecord(self, record: DnsRecord, unique: bool = False):
        def cloudflare():
            cf_zone_id = self.__get_cf_zone_id__(record.host)
            cf = CloudFlare.CloudFlare(email=self.ak, token=self.sk)
            if unique and self.check_record(record):
                return
            else:
                cf.zones.dns_records.post(cf_zone_id, data={
                    "name": record.name,
                    "type": record.rdatatype.name,
                    "content": record.value,
                    "ttl": record.ttl if record.ttl else 1,
                    'priority': 10
                })

        def namesilo():
            if record.name == "@":
                record.name = ""
            namesilo_client = NamesiloApiClient(base_url="https://www.namesilo.com/api/", access_key=self.ak)
            namesilo_client.deleteDnsRecordFromDomain(record.domain, record.id)
            return namesilo_client.addDnsRecordToDomain(record.domain, record.name, record.value, record.rdatatype.name)

        match self.code:
            case 'cloudflare':
                return cloudflare()
            case 'namesilo':
                return namesilo()
            case _:
                raise DnsException.UNSUPPORTED(self.code)

    def check_record(self, record: DnsRecord):
        return any(dns_record == record for dns_record in self.listDnsRecords(record.domain))

    @classmethod
    def code_of(cls, code) -> IDnsManager:
        return [item for item in DnsManager.values() if item.code == code][0]

    @classmethod
    def values(cls):
        _values = []
        for e in cls:
            _values.append(e)
        return _values

    @classmethod
    def to_json_array(cls):
        def to_json(el):
            return {"name": el.name, "value": el.value, "code": el.code, "label": el.label}

        return list(map(to_json, cls.values()))

    @DynamicClassAttribute
    def label(self):
        return self._label_

    @DynamicClassAttribute
    def code(self):
        return self._code_

    @DynamicClassAttribute
    def nameserver_pattern(self):
        return self._nameserver_pattern_

    def __init__(self, code, label, nameserver_pattern):
        self._code_ = code
        self._label_ = label
        self._nameserver_pattern_ = nameserver_pattern
