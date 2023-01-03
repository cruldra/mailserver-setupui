import re

import dns
from dns.rdatatype import RdataType

from src.dns.manager import DnsManager


def get_dns_manager(host) -> DnsManager:
    nameservers = "".join(get_name_server(host))

    def matcher(dns_manager):
        return re.search(dns_manager.nameserver_pattern, nameservers)

    return next(filter(matcher, DnsManager.values()))


def get_name_server(host):
    ans = dns.resolver.resolve(host, RdataType.NS)
    nameservers = []
    for rdata in ans:
        nameservers.append(str(rdata.target))
    nameservers.sort()
    return nameservers
