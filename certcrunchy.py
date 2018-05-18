#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests
import socket
import ssl
import argparse
import dns.resolver
import threading
import time
import re
import queue
from time import sleep
from tempfile import mkstemp


_banner = """\033[1;33;40m
 _____           _   _____                       _
/  __ \         | | /  __ \                     | |
| /  \/ ___ _ __| |_| /  \/_ __ _   _ _ __   ___| |__  _   _
| |    / _ \ '__| __| |   | '__| | | | '_ \ / __| '_ \| | | |
| \__/\  __/ |  | |_| \__/\ |  | |_| | | | | (__| | | | |_| |
 \____/\___|_|   \__|\____/_|   \__,_|_| |_|\___|_| |_|\__, |
                                                        __/ |
                                                       |___/
    \033[1;31;40mJust a silly recon tool...\033[0;37;40m
"""

_transparency_endpoint = "https://crt.sh/?q=%.{query}&output=json"
_censys_endpoint = "https://www.censys.io/api/v1"
_censys_uid = None
_censys_secret = None
_potential_hosts = []
_resolving_hosts = {}


def is_valid_hostname(hostname):
    if len(hostname) > 253:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def getSubjectAltNames(_potential_host):
    result = []
    try:
        socket.setdefaulttimeout(1.0)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(s, server_hostname=_potential_host)
        ssl_sock.connect((_potential_host, args.port))
        cert = ssl.DER_cert_to_PEM_cert(ssl_sock.getpeercert(True))
        tmp_file = mkstemp()
        file = open(tmp_file[1], 'w')
        file.write(cert)
        file.close()
        ssl_sock.close()
        cert = ssl._ssl._test_decode_cert(tmp_file[1])
        for i in cert["subjectAltName"]:
            if i[0] == "DNS":
                if i[1].find("*") < 0:
                    result.append(i[1])
    except socket.gaierror:
        result = None
    except socket.timeout:
        result = None
    except ssl.SSLError:
        result = None
    return result


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
                print(host)
                d = self.getARecIPs(host)
                if d:
                    self.results.put({"host": host, "ips": d})
                self.jobs.task_done()
            except queue.Empty as emp:
                pass
            except Exception as ex:
                print(ex)


def getCensysNames(domain):
    page = 1
    QUERY = "{{\"query\":\"{domain}\",\"page\":{page},\"fields\":[\"parsed.subject_dn\", \"ip\"],\"flatten\":true}}"
    hosts = []
    try:
        while 1:
            print("getting page {page}".format(page=page))
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
    print("Checking [{domain}]".format(domain=domain))
    r = requests.get(_transparency_endpoint.format(query=domain))
    if r.status_code != 200:
        print("Results not found")
        return None

    data = json.loads('[{}]'.format(r.text.replace('}{', '},{')))
    for (key, value) in enumerate(data):
        if value['name_value'].find("*") == 0:
            continue
        results.append(value['name_value'].lower())

    results = list(set(results))
    results.sort()
    return results


if __name__ == "__main__":
    print(_banner)
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', type=str, help="Domain to check")
    parser.add_argument('-D', '--domains', type=str, help="File containing the domains to check")
    parser.add_argument('-i', '--iprange', type=str, help="IP range to check certificates of")
    parser.add_argument('-o', '--output', type=str, help="Results file")
    parser.add_argument('-t', '--delay', type=int, help="Delay between quering online services", default=3)
    parser.add_argument('-p', '--port', type=int, help="Port to connect to for SSL cert", default=443)
    parser.add_argument('-U', '--uid', type=str, help="Censys.io UID")
    parser.add_argument('-S', '--secret', type=str, help="Censys.io Secret")
    args = parser.parse_args()

    _censys_uid = args.uid
    _censys_secret = args.secret

    if not args.domain and not args.domains and not args.iprange:
        print("Requires either domain, domain list or ip range")
        exit()

    if args.domain:
        print("Checking transparency archive for potential hostnames")
        _potential_hosts = getTransparencyNames(args.domain)
        if _censys_uid and _censys_secret:
            _potential_hosts = _potential_hosts + getCensysNames(args.domain)

    if args.domains:
        for domain in open(args.domains).read().split("\n"):
            _potential_hosts = _potential_hosts + getTransparencyNames(domain)
            if _censys_uid and _censys_secret:
                _potential_hosts = _potential_hosts + getCensysNames(args.domain)
            sleep(args.delay)

    print("Checking potential hostnames for DNS A records")
    threadCount = 20

    threads = []
    q = queue.Queue()
    for h in _potential_hosts:
        q.put(h)
    r = queue.Queue()

    for i in range(threadCount):
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

    print("Found [{count}] resolving hostnames".format(count=len(_resolving_hosts)))
    for _host in _resolving_hosts:
        print("  {host} => [{ips}]".format(host=_host, ips=", ".join(_resolving_hosts[_host])))
    print("")
