from types import DynamicClassAttribute

from dns.rdatatype import RdataType


class DnsRecord:
    __id__: str
    __host__: str
    __name__: str
    __value__: str
    __rdatatype__: RdataType
    __ttl__: int

    def __eq__(self, other):
        if self.id == other['id']:
            return True
        elif self.rdatatype.name == other['type'] and self.value == other['content']:
            if f"{self.name}.{self.host}" == other['name']:
                return True
            elif self.name == "@" and self.host == other['name']:
                return True
        return False

    @classmethod
    def from_dict(cls, dic: dict):
        return DnsRecord(host=dic['host'],
                         name=dic['name'],
                         value=dic['value'],
                         ttl=dic.get('ttl'),
                         rdatatype=RdataType(dic['type']))

    @DynamicClassAttribute
    def id(self):
        return self.__id__

    @DynamicClassAttribute
    def host(self):
        return self.__host__

    @DynamicClassAttribute
    def name(self):
        return self.__name__

    @DynamicClassAttribute
    def value(self):
        return self.__value__

    @DynamicClassAttribute
    def rdatatype(self):
        return self.__rdatatype__

    @DynamicClassAttribute
    def ttl(self):
        return self.__ttl__

    def to_json(self):
        return {
            "host": self.host,
            "name": self.name,
            "value": self.value,
            "type": self.rdatatype
        }

    def __init__(self, host, name, value, rdatatype: RdataType = RdataType.A, ttl: int = 0, id=""):
        self.__id__ = id
        self.__host__ = host
        self.__name__ = name
        self.__value__ = value
        self.__rdatatype__ = rdatatype
        self.__ttl__ = ttl

    def __str__(self) -> str:
        return f"{self.name}.{self.host}"

    def __repr__(self) -> str:
        return f"{self.name}.{self.host}"