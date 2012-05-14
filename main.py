#!/usr/bin/python2 -u

import sys
import json

import nmap
from matplotlib import pyplot


class Task:
    pass


class PortsStat(Task):
    '''Scan a subnet for open port statistics.'''
    pass


class Uphosts(Task):
    '''Scan a series of subnets for online hosts.'''
    def __init__(self, template, xs):
        self.template = template
        self.xs = xs

    def scan(self):
        results = []
        for x in self.xs:
            net = template.format(x=x)
            nm = nmap.PortScanner()
            #try:
            if 1:
                nm.scan(net, arguments='-sn -T4')
                uphosts = int(nm.scanstats()['uphosts'])
            else:
            #except nmap.PortScannerError:
                uphosts = None
            results.append((x, uphosts))
        return results

    def plot(self, results):
        xs, ys = zip(*results)
        ys = [y or 0 for y in ys]
        pyplot.show(pyplot.bar(xs, ys))


def main():
    uh = Uphosts('59.66.{x}.0/24', range(256))
    re = uh.scan()
    json.dump(re, sys.stdout, indent=2)


if __name__ == '__main__':
    main()

