#!/usr/bin/python3

import sys
import requests
import xml.etree.ElementTree as et

USAGE = "Usage: ./nmap-hsts.py nmap.xml"

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

class Host(object):
    def __init__(self):
        self.address = ''
        self.hostnames = []
        self.http_ports = []
        self.https_ports = []


def parse_services(f):
    tree = et.parse(f)

    hosts = []
    for node in tree.findall('.//host'):
        host = Host()
        host.address = node.find('address').attrib['addr']
        host.hostnames.append(host.address)
        for hostname in node.findall('.//hostname'):
            host.hostnames.append(hostname.attrib['name'])
        for port in node.findall('.//port'):
            try:
                service = port.find('service').attrib
            except AttributeError:
                continue
            if port.find('state').attrib['state'] != 'open':
                continue
            if port.attrib['protocol'] == 'tcp' and service['name'] == 'http':
                try:
                    if service['tunnel'] == 'ssl':
                        host.https_ports.append(port.attrib['portid'])
                except KeyError:
                    host.http_ports.append(port.attrib['portid'])
        hosts.append(host)

    return hosts


def request_service(hostname, port, is_ssl):
    if is_ssl:
        url = "https://{}:{}/".format(hostname, port)
    else:
        url = "http://{}:{}/".format(hostname, port)
    print("Requesting {}...".format(url))

    try: 
        r = requests.get(url, proxies=proxies, verify=False, timeout=3, allow_redirects=False)
    except requests.exceptions.ReadTimeout:
        print("{} timed out.".format(url))
        return None

    return r


def check_hsts(r):
    return 'strict-transport-security' in r.headers.keys()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(USAGE)
        sys.exit(1)

    hosts = parse_services(sys.argv[1])
    for host in hosts:
        for port in host.http_ports:
            for hostname in host.hostnames:
                r = request_service(hostname, port, False)
                if r and not check_hsts(r):
                    print("http://{}:{}/ does not set a Strict-Transport Security Header!".format(hostname, port))
                    #TODO: figure out how to reconstruct the pretty, ordered headers that burp's response tab shows
        for port in host.https_ports:
            for hostname in host.hostnames:
                r = request_service(hostname, port, True)
                if r and not check_hsts(r):
                    print("https://{}:{}/ does not set a Strict-Transport Security Header!".format(hostname, port))
                    #TODO: figure out how to reconstruct the pretty, ordered headers that burp's response tab shows

    