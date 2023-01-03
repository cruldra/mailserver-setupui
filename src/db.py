from enum import Enum
from types import DynamicClassAttribute


class Database(Enum):
    MYSQL = ("mysql", "mysql")
    POSTGRESQL = ("postgresql", "postgresql")
    _code_: str
    _label_: str

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

    def __init__(self, code, label):
        self._code_ = code
        self._label_ = label
