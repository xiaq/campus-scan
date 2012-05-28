#!/usr/bin/python2 -u

import os
import sys
import json

import nmap
import ipaddr
import numpy as np
from matplotlib import mlab, pyplot as plt


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
            try:
                nm.scan(net, arguments='-sn -T4')
                uphosts = int(nm.scanstats()['uphosts'])
            except nmap.PortScannerError:
                # NOTE The only known cause of exception here is "RTTVAR has
                # grown to over 2.3 seconds, decreasing to 2.0"
                uphosts = None
            sys.stderr.write('%d %s %r\n' % (x, net, uphosts))
            results.append((x, uphosts))
        return results

    @classmethod
    def plot(cls, results, folder):
        def make_fname(name):
            return os.path.join(folder, name)

        xs, ys = zip(*results)
        ys = [y or 0 for y in ys]

        # XXX hardcoded
        plt.suptitle('uphosts of 59.66.x.0/24')
        plt.gcf().set_size_inches(10, 40)
        plt.xticks(np.arange(5) * 64)
        plt.yticks(np.arange(256))
        plt.grid()
        plt.axis([0, 256, 255, 0])
        plt.barh(xs, ys, align='center', linewidth=2)
        plt.savefig(make_fname('uphosts.png'))
        plt.close()

        bins = np.arange(17) * 16

        plt.suptitle('uphosts of 59.66.x.0/24: distribution')
        plt.hist(ys, bins)
        plt.xticks(bins)
        plt.savefig(make_fname('uphosts-dist.png'))
        plt.close()

def main():
    def _usage():
        raise ValueError
        #sys.stderr.write('Usage: no doc yet\n')
        #sys.exit(1)

    if len(sys.argv) < 2:
        _usage()

    SCAN = 'scan'
    PLOT = 'plot'
    UPHOSTS = 'uphosts'
    OPENPORTS = 'openports'

    # XXX handmade option parser
    task, verb = sys.argv[1:3]
    additional = sys.argv[3:]
    if verb == SCAN:
        if os.getuid() != 0:
            sys.stderr.write('Warning: Not scanning as root. '
                             'Performance may be degraded.\n')
        if task == UPHOSTS:
            worker = UpHosts('59.66.{x}.0/24', range(256))
        elif task == OPENPORTS:
            subnet = additional and additional[0] or '59.66.0.0/16'
            worker = OpenPorts(subnet)
        else:
            _usage()
        json.dump(worker.scan(), sys.stdout)
    elif verb == PLOT:
        results = json.load(sys.stdin)
        folder = additional and additional[0] or '.'
        if task == UPHOSTS:
            UpHosts.plot(results, folder)
        elif task == OPENPORTS:
            raise NotImplementedError
        else:
            _usage()
    else:
        _usage()


if __name__ == '__main__':
    main()

