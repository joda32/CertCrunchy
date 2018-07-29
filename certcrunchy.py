#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import itertools
import requests
import socket
import ssl
import argparse
import dns.resolver
import threading
import time
import re
import queue
import ipaddress
import api_keys
import socket
from time import sleep
from tempfile import mkstemp


_banner = """\033[1;33;49m
 _____           _   _____                       _
/  __ \         | | /  __ \                     | |
| /  \/ ___ _ __| |_| /  \/_ __ _   _ _ __   ___| |__  _   _
| |    / _ \ '__| __| |   | '__| | | | '_ \ / __| '_ \| | | |
| \__/\  __/ |  | |_| \__/\ |  | |_| | | | | (__| | | | |_| |
 \____/\___|_|   \__|\____/_|   \__,_|_| |_|\___|_| |_|\__, |
                                                        __/ |
                                                       |___/
    \033[1;31;49mJust a silly recon tool...
    @_w_m__\033[0;37;49m
"""

_transparency_endpoint = "https://crt.sh/?q=%.{query}&output=json"
_censys_endpoint = "https://www.censys.io/api/v1"
_certdb_endpoint = "https://certdb.com/api?q={query}"
_certspotter_endpoint = "https://certspotter.com/api/v0/certs?domain={query}"
_vt_domainsearch_endpoint = "https://www.virustotal.com/vtapi/v2/domain/report"
_vt_ipsearch_endpoint = "https://www.virustotal.com/vtapi/v2/ip-address/report"
_riskiq_endpoint = "https://api.passivetotal.org"
_potential_hosts = []
_resolving_hosts = {}
_port = 443
_threads = 20
_delay = 3


def is_valid_hostname(hostname):
    if len(hostname) > 253:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # Strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


class certThread(threading.Thread):
    def __init__(self, jobqueue, resultqueue):
        threading.Thread.__init__(self)
        self.jobs = jobqueue
        self.results = resultqueue
        self.stop_received = False

    def getNames(self, _potential_host, _port):
        result = []
        try:
            socket.setdefaulttimeout(1.0)
            context = ssl.create_default_context()
            context.check_hostname = False  # Disable check for SNI host
            conn = context.wrap_socket(socket.socket(socket.AF_INET))
            conn.connect((_potential_host, _port))
            cert = conn.getpeercert()
            for i in cert["subject"]:
                if i[0][0] == "commonName":
                    if i[0][1].find("*") < 0:
                        result.append(i[0][1])
                        print("[Found] {}".format(i[0][1]))
                    else:
                        result.append(i[0][1][2:])
                        print("[Found] {}".format(i[0][1][2:]))
            if "subjectAltName" in cert:
                for i in cert["subjectAltName"]:
                    if i[0][0] == "DNS":
                        if i[0][1].find("*") < 0:
                            result.append(i[0][1])
                            print("[Found] {}".format(i[0][1]))
                        else:
                            result.append(i[0][1][2:])
                            print("[Found] {}".format(i[0][1][2:]))
        except socket.gaierror:
            result = None
        except socket.timeout:
            result = None
        except ssl.SSLError:
            result = None
        except ConnectionResetError:
            result = None
        except ConnectionRefusedError:
            result = None
        except OSError:
            result = None
        return result

    def stop(self):
        self.stop_received = True

    def run(self):
        while not self.stop_received:
            try:
                host = self.jobs.get_nowait()
                #print(host)
                d = self.getNames(host, _port)
                if d:
                    self.results.put(d)
                self.jobs.task_done()
            except queue.Empty as emp:
                pass
            except Exception as ex:
                print(ex)
                raise ex
                


class dnsThread(threading.Thread):
    def __init__(self, jobqueue, resultqueue):
        threading.Thread.__init__(self)
        self.jobs = jobqueue
        self.results = resultqueue
        self.stop_received = False

    def getARecIPs(self, hostname):
        result = []
        try:
            for answer in dns.resolver.query(hostname, "A"):
                result.append(answer.to_text())
        except Exception as ex:
            result = None
        return result

    def stop(self):
        self.stop_received = True

    def run(self):
        while not self.stop_received:
            try:
                host = self.jobs.get_nowait()
                #print(host)
                d = self.getARecIPs(host)
                if d:
                    self.results.put({"host": host, "ips": d})
                self.jobs.task_done()
            except queue.Empty as emp:
                pass
            except Exception as ex:
                print(ex)


def getNamesFromIps(ip_range):
    print("Checking potential hostnames for netblock")
    ips = []
    results = []
    for i in ipaddress.ip_network(ip_range):
        ips.append(str(i))
    threads = []
    q = queue.Queue()
    for h in ips:
        q.put(h)
    r = queue.Queue()

    for i in range(_threads):
        worker = certThread(q, r)
        worker.setDaemon(True)
        worker.start()
        threads.append(worker)

    while not q.empty():
        time.sleep(1)

    for worker in threads:
        worker.stop()

    for worker in threads:
        worker.join()

    for _host in list(r.queue):
        results.append(_host)
    results = list(itertools.chain.from_iterable(results))
    return list(set(results))


def getCensysNames(domain):
    print("[Censys.io] Checking [{domain}]".format(domain=domain))
    page = 1
    QUERY = "{{\"query\":\"{domain}\",\"page\":{page},\"fields\":[\"parsed.subject_dn\", \"ip\"],\"flatten\":true}}"
    hosts = []
    try:
        while 1:
            #print("getting page {page}".format(page=page))
            data = QUERY.format(domain=domain, page=page)
            res = requests.post(_censys_endpoint + "/search/certificates", data=data, auth=(_censys_uid, _censys_secret))
            if res.status_code != 200:
                print("error occurred: {error}".format(res.json()["error"]))
                break

            for r in res.json()["results"]:
                if "CN" in r["parsed.subject_dn"]:
                    # There is some weirdness with some CN's not being propperly parsed, thus getting some shit output
                    name = r["parsed.subject_dn"].split("CN=")[1].lower()
                    if name.find(",") > -1:
                        name = name.split(",")[0]
                    if is_valid_hostname(name):
                        if not name.find("*") == 0:
                            if name.find("." + domain) > -1:
                                hosts.append(name)

            if len(res.json()["results"]) < 100:
                break
            page += 1
            if page == 101:
                print("Can't go past page 100")
                break

    except Exception as ex:
        print(ex)
    hosts = list(set(hosts))
    return hosts


def getTransparencyNames(domain):
    results = []
    print("[crt.sh] Checking [{domain}]".format(domain=domain))
    r = requests.get(_transparency_endpoint.format(query=domain))
    if r.status_code != 200:
        print("Results not found")
        return results

    data = json.loads('[{}]'.format(r.text.replace('}{', '},{')))
    for (key, value) in enumerate(data):
        if value['name_value'].find("*") == 0:
            continue
        results.append(value['name_value'].lower())

    results = list(set(results))
    results.sort()
    return results


def getPassiveTotalNames(domain):
    results = []
    auth = (api_keys._riskiq_user, api_keys._riskiq_key)
    endpoint = "{}/{}".format(_riskiq_endpoint, "/v2/enrichment/subdomains")
    data = {'query': domain}
    try:
        r = requests.get(endpoint, auth=auth, json=data)
        if r.status_code != 200:
            print("Results not found")
            return results
        result = r.json()
        if result["subdomains"]:
            for prefix in result["subdomains"]:
                results.append("{}.{}".format(prefix, domain))
    except Exception as ex:
        print("Error [{}]".format(ex))
    results = list(set(results))
    results.sort()
    return results
    

def getDomainVTNames(domain):
    results = []
    print("[virustotal.com] Checking [{domain}]".format(domain=domain))
    params = {"apikey": api_keys._virustotal, "domain": domain}
    r = requests.get(_vt_domainsearch_endpoint, params=params)
    if r.status_code != 200:
        print("Results not found")
        return results
    data = json.loads('[{}]'.format(r.text.replace('}{', '},{')))
    for items in data:
        for subdomain in items["subdomains"]:
            results.append(subdomain.strip().lower())

    results = list(set(results))
    results.sort()
    return results


def getIPVTNames(ip_range):
    results = []
    print("[virustotal.com] Checking [{ip_range}]".format(ip_range=ip_range))
    for ip in ipaddress.ip_network(ip_range):
        params = {"apikey": api_keys._virustotal, "ip": ip}
        print("Checking [{}]".format(ip))
        from pprint import pprint
        r = requests.get(_vt_domainsearch_endpoint, params=params)
        if r.status_code != 200:
            pprint(r)
            print("Results not found")
            break
        from pprint import pprint
        data = json.loads(r.text)
        if data["response_code"] == 1:
            for subdomain in data["resolutions"]:
                results.append(subdomain["hostname"].strip().lower())
        sleep(15)

    results = list(set(results))
    results.sort()
    return results


def getIPReverseLookup(ip_range):
    results = []
    print("[PTR names] Checking [{ip_range}]".format(ip_range=ip_range))
    for ip in ipaddress.ip_network(ip_range):
        try:
            (name, l_arpa, l_ip, )=socket.gethostbyaddr(str(ip))
            results.append(name.strip().lower())
        except socket.herror:
            pass

    results = list(set(results))
    results.sort()
    return results


def getCertDBNames(domain):
    results = []
    print("[CertDB] Checking [{domain}]".format(domain=domain))
    r = requests.get(_certdb_endpoint.format(query=domain))
    if r.status_code != 200:
        print("Results not found")
        return results
    
    data = json.loads('[{}]'.format(r.text.replace('}{', '},{')), strict=False)
    for certs in data:
        for cert in certs:
            if "subject" in cert:
                cn = cert["subject"]["CN"].lower()
                if cn.find("*") > -1:
                    cn = cn[2:]
                results.append(cn)
            if "extensions" in cert:
                if "subjectAltName" in cert["extensions"]:
                    altnames = cert["extensions"]["subjectAltName"].split(",")
                    if altnames:
                        if len(altnames) > 0:
                            for b in altnames:
                                aname = b.split(":")[1].lower()
                                if aname.find("*") > -1:
                                    aname = aname[2:]
                                results.append(aname)

    results = list(set(results))
    results.sort()
    return results


def getCertSpotterNames(domain):
    results = []
    print("[CertSpotter] Checking [{domain}]".format(domain=domain))
    r = requests.get(_certspotter_endpoint.format(query=domain))
    if r.status_code != 200:
        print("Results not found")
        return results
    
    data = json.loads(r.text, strict=False)
    for certs in data:
        for names in certs["dns_names"]:
            if names.find("*") > -1:
                names = names[2:]
            results.append(names)

    results = list(set(results))
    results.sort()
    return results


if __name__ == "__main__":
    print(_banner)
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', type=str, help="Domain to check")
    parser.add_argument('-D', '--domains', type=str, help="File containing the domains to check")
    parser.add_argument('-i', '--iprange', type=str, help="IP range to check certificates of eg. 10.0.0.0/24")
    parser.add_argument('-o', '--output', type=str, help="Results file")
    parser.add_argument('-f', '--format', type=str, help="Output format [csv/json] defaut csv", default="csv")
    parser.add_argument('-t', '--delay', type=int, help="Delay between quering online services", default=3)
    parser.add_argument('-T', '--threads', type=int, help="Number of concurrent threads", default=20)
    parser.add_argument('-p', '--port', type=int, help="Port to connect to for SSL cert", default=443)
    parser.add_argument('-V', '--virustotal', action="store_true", help="When using an IP range and VT api is set, query VT for IP #WARNING, it takes a long time", default=False)
    args = parser.parse_args()

    _port = args.port
    _threads = args.threads
    _domains = []
    _delay = args.delay

    if not args.domain and not args.domains and not args.iprange:
        print("Requires either domain, domain list or ip range")
        exit()

    if args.domain:
        _domains.append(args.domain)
    if args.domains:
        for domain in open(args.domains).read().split("\n"):
            if len(domain) > 3:
                _domains.append(domain)

    if len(_domains) < 1 and not args.iprange:
        print("We need some domains to work with.")
        exit()
        

    for domain in _domains:
        # Start with crt.sh
        _potential_hosts = _potential_hosts + getTransparencyNames(domain)
        # Next check CertDB
        _potential_hosts = _potential_hosts + getCertDBNames(domain)
        # Next check CertSpotter
        _potential_hosts = _potential_hosts+ getCertSpotterNames(domain)
        # Next, if API key is set for Censys, then do that
        if api_keys._censys_uid and api_keys._censys_secret:
            _potential_hosts = _potential_hosts + getCensysNames(domain)
        if api_keys._virustotal:
            _potential_hosts = _potential_hosts + getDomainVTNames(domain)
        if api_keys._riskiq_user and api_keys._riskiq_key:
            _potential_hosts = _potential_hosts + getPassiveTotalNames(domain)
        sleep(_delay)

    if args.iprange:
        _potential_hosts = getNamesFromIps(args.iprange)
        _potential_hosts = _potential_hosts + getIPReverseLookup(args.iprange)
        if api_keys._virustotal and args.virustotal:
            _potential_hosts = getIPVTNames(args.iprange)

    print("Checking potential hostnames for DNS A records")

    threads = []
    q = queue.Queue()
    for h in _potential_hosts:
        q.put(h)
    r = queue.Queue()

    for i in range(_threads):
        worker = dnsThread(q, r)
        worker.setDaemon(True)
        worker.start()
        threads.append(worker)

    while not q.empty():
        time.sleep(1)

    for worker in threads:
        worker.stop()

    for worker in threads:
        worker.join()

    for _host in list(r.queue):
        _resolving_hosts[_host["host"]] = _host["ips"]

    if args.output:
        with open(args.output, "w") as f:
            if args.format == "csv":
                for _host in _resolving_hosts:
                    f.write("{},{}\n".format(_host, ",".join(_resolving_hosts[_host])))
            else:
                json.dump(_resolving_hosts, f)
            f.close()
    print("Found [{count}] resolving hostnames".format(count=len(_resolving_hosts)))
    for _host in _resolving_hosts:
        print("[Resolving] {host} => [{ips}]".format(host=_host, ips=", ".join(_resolving_hosts[_host])))
    print("")
