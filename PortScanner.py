#!/usr/bin/env python3
# encoding: utf-8

import argparse
from socket import *
from threading import *
import nmap
import csv


# Multi-Thread support
screenLock = Semaphore(value=1)


def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(1024)
        screenLock.acquire()
        print('[+] %d/tcp open' % tgtPort)
        print('[+] ' + str(results))
    except:
        screenLock.acquire()
        print('[-] %d/tcp closed' % tgtPort)
    finally:
        screenLock.release()
        connSkt.close()


def portScan(tgtHost, tgtPorts, useNmap=False):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print('[-] Connot resolve "%s": Unknown host' % str(tgtHost))
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan results for: ' + tgtName[0])
    except:
        print('\n[+] Scan results for: ' + tgtIP)
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        if bool(useNmap):
            nmapScan(tgtHost, tgtPort)
        else:
            t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
            t.start()


def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, tgtPort)
    state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print('- [*] %s tcp/%s %s' % (tgtHost, tgtPort.strip(), state))


def readPortsFromCSV(path='SCANPORTS.csv'):
    ports = []
    with open(path, newline='') as csvfile:
        payload = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in payload:
            ports += row
    return ports


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A network sniffer with nmap embedded')
    parser.add_argument('--host', help='Specify target host')
    parser.add_argument('--port', help='Specify target port')
    parser.add_argument('--nmap', help='Use Nmap as a default network sniffer')

    args = parser.parse_args()
    tgtHost = args.host
    tgtPorts = [args.port] if args.port is not None else readPortsFromCSV()
    if not tgtHost or not tgtPorts:
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts, args.nmap)
