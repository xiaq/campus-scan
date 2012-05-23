#!/usr/bin/python2 -u

import os
import sys
import json

import nmap
import ipaddr
from matplotlib import pyplot


class Task:
    pass


# nmap arguments used:
# -sn ping scan only
# -T4 quick scan
# -F  scan only the most popular 100 ports

class OpenPorts(Task):
    '''Scan a subnet for open port statistics.'''
    def __init__(self, subnet):
        self.net = ipaddr.IPv4Network(subnet)
        self.addrs = [addr.exploded for addr in self.net]

    def scan(self):
        services = ''
        results = []
        for addr in self.addrs:
            nm = nmap.PortScanner()
            #try:
            if 1:
                result = nm.scan(addr, arguments='-T4 -F')
                if not services:
                    services = result['nmap']['scaninfo']['tcp']['services']

                if not result['scan'].has_key(addr):
                    sys.stderr.write('%s: no info\n' % addr)
                    continue
                ports_stat = result['scan'][addr].get('tcp', {})
                open_ports = []
                for p, info in ports_stat.items():
                    if info['state'] == u'open':
                        open_ports.append(p)
                sys.stderr.write('%s %r\n' % (addr, open_ports))
                results.append((addr, open_ports))
            #except nmap.PortScannerError:
            else:
                pass
        return results


class UpHosts(Task):
    '''Scan a series of subnets for online hosts.'''
    def __init__(self, template, xs):
        self.template = template
        self.xs = xs

    def scan(self):
        results = []
        for x in self.xs:
            net = self.template.format(x=x)
            nm = nmap.PortScanner()
            #try:
            if 1:
                nm.scan(net, arguments='-sn -T4')
                uphosts = int(nm.scanstats()['uphosts'])
            else:
            #except nmap.PortScannerError:
                uphosts = None
            sys.stderr.write('%d %s %d\n' % (x, net, uphosts))
            results.append((x, uphosts))
        return results

    @classmethod
    def plot(cls, results):
        xs, ys = zip(*results)
        ys = [y or 0 for y in ys]
        pyplot.show(pyplot.bar(xs, ys))


def main():
    def _usage():
        raise ValueError
        sys.stderr.write('Usage: no doc yet\n')
        sys.exit(1)
        
    if os.getuid() != 0:
        sys.stderr.write('Warning: Not running as root. '
                         'Performance may be degraded.\n')

    if len(sys.argv) < 2:
        _usage()

    SCAN = 'scan'
    PLOT = 'plot'
    UPHOSTS = 'uphosts'
    OPENPORTS = 'openports'

    task, verb = sys.argv[1:3]
    if verb == SCAN:
        if task == UPHOSTS:
            worker = UpHosts('59.66.{x}.0/24', range(256))
        elif task == OPENPORTS:
            worker = OpenPorts('59.66.0.0/16')
        else:
            _usage()
        json.dump(worker.scan(), sys.stdout)
    elif verb == PLOT:
        results = json.load(sys.stdin)
        if task == UPHOSTS:
            UpHosts.plot(results)
        elif task == OPENPORTS:
            raise NotImplementedError
        else:
            _usage()
    else:
        _usage()


if __name__ == '__main__':
    main()

