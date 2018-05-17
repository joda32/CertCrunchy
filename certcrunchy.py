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
from tempfile import mkstemp
import queue

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


if __name__ == "__main__":
    print(_banner)


_potential_hosts = []
_resolving_hosts = {}

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--domain', type=str, required=True, help="Domain to check")
parser.add_argument('-o', '--output', type=str, help="Results file")
parser.add_argument('-p', '--port', type=int, help="Port to connect to for SSL cert", default=443)
args = parser.parse_args()

print("Checking archive for potential hostnames")
r = requests.get(_endpoint.format(query=args.domain))
if r.status_code != 200:
    print("Results not found")
    exit()

data = json.loads('[{}]'.format(r.text.replace('}{', '},{')))
for (key, value) in enumerate(data):
    _potential_hosts.append(value['name_value'].lower())

_potential_hosts = list(set(_potential_hosts))
_potential_hosts.sort()

print("Found [{count}] potential hostnames".format(count=len(_potential_hosts)))
for name in _potential_hosts:
    print("  {host}".format(host=name))

print("")

_resolving_hosts = {}

print("Checking potential hostnames for DNS A records")
threadCount = 20

threads = []
q = queue.Queue()
for h in _potential_hosts:
    q.put(h)
r = queue.Queue()

#for _potential_host in _potential_hosts:
#    ips = getARecIPs(_potential_host)
#    if ips:

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

print("Checking resolved hostnames for additional subjectAltname hosts")
_potential_hosts = []
for _host in _resolving_hosts:
    _h = getSubjectAltNames(_host)
    if (_h):
        _potential_hosts = _potential_hosts + getSubjectAltNames(_host)
_potential_hosts = list(set(_potential_hosts))
_potential_hosts.sort()

print("Found [{count}] SubjectAltNames".format(count=len(_potential_hosts)))
print("Checking for previously unseen hostnames")

threadCount = 20

threads = []
q = queue.Queue()
for _host in _potential_hosts:
    if not _resolving_hosts.get(_host):
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

for _host in _resolving_hosts:
    print("  {host} => [{ips}]".format(host=_host, ips=", ".join(_resolving_hosts[_host])))
