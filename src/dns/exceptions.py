class DnsException(Exception):
    def __init__(self, msg: str, cause=None):
        super().__init__(msg, cause)

    @staticmethod
    def UNSUPPORTED(code: str) -> 'DnsException':
        return DnsException(f"dns管理器{code}暂未提供支持")
