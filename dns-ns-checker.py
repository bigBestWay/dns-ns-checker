import ipaddress
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


# 先使用NS Query简单检查，如果没有错误，再单独在NS服务器上查询
def __check_ns_query_error(domain, nameserver_host='8.8.8.8'):
    name = dns.name.from_text(domain)
    q = dns.message.make_query(qname=name, rdtype=dns.rdatatype.NS, use_edns=True, flags=dns.flags.RD | dns.flags.AD)
    # print("The query is:")
    # print(q)
    # print("")

    if is_ip_str(nameserver_host) is False:
        a_records = query_a_records(nameserver_host)
        if len(a_records) == 0:
            return True
        # 有多条记录，只取第1条
        nameserver_host = a_records[0]

    r = dns.query.udp(q=q, where=nameserver_host)
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
    except dns.resolver.NoNameservers:
        pass
    except dns.resolver.LifetimeTimeout:
        pass
    except dns.resolver.NoAnswer:  # 没有应答
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as e:
        print(type(e))
        print(e)
    return ns_servers


def query_ns_records(domain):
    results = set()
    with ThreadPoolExecutor(max_workers=len(GLOBAL_DNS_SERVER_LIST)) as t:
        obj_list = []
        for k, dns_server in GLOBAL_DNS_SERVER_LIST.items():
            obj = t.submit(__query_ns_records_worker, domain, dns_server)
            obj_list.append(obj)

        for future in as_completed(obj_list):
            data = future.result()
            # print(f"query_ns_records: {domain}->{data}")
            for d in data:
                results.add(d)
    return results


def query_a_records(domain):
    ips = []
    try:
        myResolver = dns.resolver.Resolver()
        myResolver.nameservers = ['114.114.114.114', '8.8.8.8']
        myAnswers = myResolver.resolve(domain, 'A')
        if myAnswers.rrset is not None:
            for item in myAnswers.rrset.items:
                ips.append(item.address)
    except dns.resolver.NXDOMAIN:
        print('The DNS query name does not exist:' + domain)
        pass
    except dns.resolver.NoAnswer:
        print('The DNS response does not contain an answer to the question:' + domain)
        pass
    return ips


def vulnerable_check(parent_domain):
    # 先默认执行一次NS查询，如果有错误就直接返回
    nameservers = query_ns_records(parent_domain)
    print(f'{parent_domain} NS Record Values:')
    if len(nameservers) > 0:
        print(nameservers)
    else:
        print('NULL')

    if __check_ns_query_error(parent_domain) is True:
        return True

    # 没有错误，就要查询出该子域的NS服务，然后逐个指定NS服务去进一步查询，判断有没有错误
    for host in nameservers:
        if __check_ns_query_error(parent_domain, host) is True:
            return True
    return False


def usage():
    print(f'dns-ns-checker.py <DOMAIN>')
    print(f'dns-ns-checker.py -r <DOMAIN_LIST_FILE>')


def parent_name(name):
    p = name.find('.')
    if p != -1:
        return name[p + 1:]
    return name


def is_ip_str(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception as e:
        return False


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1].strip() == '-r':
        parent_domains = []
        with open(sys.argv[2].strip(), 'r') as f:
            for name in f.readlines():
                parent_domains.append(parent_name(name.strip()))
        parent_domains = set(parent_domains)
        print(parent_domains)
        for name in parent_domains:
            if vulnerable_check(name.strip()):
                print(f'!!! {name} is vulnerable.')
            else:
                print(f'{name} is not vulnerable.')
            print('--------------------------------------')
    elif len(sys.argv) == 2:
        name = sys.argv[1].strip()
        if vulnerable_check(name.strip()):
            print(f'!!! {name} is vulnerable. ')
        else:
            print(f'{name} is not vulnerable.')
    else:
        usage()
        exit(1)
