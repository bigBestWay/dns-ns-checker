import sys
import dns.resolver
from dns.edns import EDECode
from concurrent.futures import ThreadPoolExecutor, as_completed


# https://dnschecker.org/
GLOBAL_DNS_SERVER_LIST = {
    'OpenDNS': '208.67.222.220',
    'Google': '8.8.8.8',
    'Quad9_1': '9.9.9.9',
    'AT&T Services': '12.121.117.201',
    'Quad9_2': '149.112.112.112',
    'NeuStar': '156.154.70.64',
    'Fortinet Inc': '208.91.112.53',
    'IONICA LLC': '176.103.130.130',
    'Liquid Telecommunications Ltd': '5.11.11.5',
    'Pyton Communication Services B.V.': '193.58.204.59',
    'Association Gitoyen': '80.67.169.40',
    'Prioritytelecom Spain S.A.': '212.230.255.1',
    'Oskar Emmenegger': '194.209.157.109',
    'nemox.net': '83.137.41.9',
    '4D Data Centres Ltd': '37.209.219.30',
    'Verizon Deutschland GmbH': '194.172.160.4',
    'Marcatel Com': '200.56.224.11',
    'Universo Online S.A': '200.221.11.100',
    'TT Dotcom Sdn Bhd': '211.25.206.147',
    'Cloudflare Inc': '1.1.1.1',
    'Pacific Internet': '61.8.0.113',
    'SiteHost': '223.165.64.97',
    'Tefincom S.A.': '103.86.99.100',
    'LG Dacom Corporation': '164.124.101.2',
    'Shenzhen Sunrise Technology Co. Ltd.': '202.46.34.75',
    'Teknet Yazlim': '31.7.37.37',
    'Kappa Internet Services Private Limited': '115.178.96.2',
    'CMPak Limited': '209.150.154.1',
    'CLOUDITY Network': '185.83.212.30',
    'Daniel Cid': '185.228.168.9'
}


def vulnerable_check(domain):
    name = dns.name.from_text(domain)
    q = dns.message.make_query(qname=name, rdtype=dns.rdatatype.NS, use_edns=True, flags=dns.flags.RD | dns.flags.AD)
    # print("The query is:")
    # print(q)
    # print("")

    r = dns.query.udp(q, "8.8.8.8")
    # print("The response is:")
    # print(r)
    # print("")

    # 如果存在SERVFAIL或者REFUSED错误，证明存在NS错误
    if r.rcode() == dns.rcode.Rcode.SERVFAIL or r.rcode() == dns.rcode.Rcode.REFUSED:
        # The EDNS options, a list of dns.edns.Option objects. The default is the empty list.
        if len(r.options) > 0:
            for opt in r.options:
                if opt.code == EDECode.NETWORK_ERROR:
                    print(opt.text)
        return True
    return False


def __query_ns_records_worker(domain, dns_server):
    ns_servers = []
    try:
        answer = dns.resolver.resolve_at(where=dns_server, qname=domain, rdtype="NS")
        for rr in answer:
            ns_servers.append(str(rr.target))
    except Exception as e:
        pass
    return ns_servers


def query_ns_records(domain):
    results = []
    with ThreadPoolExecutor(max_workers=len(GLOBAL_DNS_SERVER_LIST)) as t:
        obj_list = []
        for k, dns_server in GLOBAL_DNS_SERVER_LIST.items():
            obj = t.submit(__query_ns_records_worker, domain, dns_server)
            obj_list.append(obj)

        for future in as_completed(obj_list):
            data = future.result()
            # print(f"query_ns_records: {domain}->{data}")
            results += data
    return set(results)


def usage():
    print(f'dns-ns-checker.py <DOMAIN>')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
        exit(1)

    name = sys.argv[1]
    if vulnerable_check(name):
        print(f'{name} is vulnerable. Here are NS Records:')
        print(query_ns_records(name))
