from dns.rdatatype import RdataType


class Domain:
    def __init__(self, created, expires, domain):
        self.created = created
        self.expires = expires
        self.domain = domain


class DnsRecord:
    def __init__(self, domain, name, value, rdatatype: RdataType = RdataType.A, ttl: int = 0, id=""):
        """
        创建一个DNS记录
        :param domain: 域名
        :param name: 记录名称
        :param value: 记录值
        :param rdatatype: 记录类型
        :param ttl: 记录在dns服务器的缓存时间
        :param id: 记录的id
        """
        self.domain = domain
        self.name = name
        self.value = value
        self.rdatatype = rdatatype
        self.ttl = ttl
        self.id = id

    def __eq__(self, other):
        if isinstance(other, DnsRecord):
            if self.id == other.id:
                return True
            else:
                return self.domain == other.domain and self.name == other.name and self.value == other.value and self.rdatatype == other.rdatatype
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def from_dict(cls, dic: dict):
        return DnsRecord(domain=dic['domain'],
                         name=dic['name'],
                         value=dic['value'],
                         ttl=dic.get('ttl'),
                         rdatatype=RdataType(dic['type']))

    def to_json(self):
        return {
            "domain": self.domain,
            "name": self.name,
            "value": self.value,
            "type": self.rdatatype
        }

    def __str__(self) -> str:
        if self.name == "":
            return f'@.{self.domain}'
        return f"{self.name}.{self.domain}"

    def __repr__(self) -> str:
        if self.name == "":
            return f'@.{self.domain}'
        return f"{self.name}.{self.domain}"
