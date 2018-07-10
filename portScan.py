# -*- coding: utf-8 -*-
import time
import sys
import os
import re
import subprocess
import threading
import nmap
from argparse import ArgumentParser


def color_print(msg, color='red', exit=False):
    color_msg = {'green': '\033[36m{0}\033[0m',
                 'yellow': '\033[32m{0}\033[0m',
                 'orange': '\033[33m{0}\033[0m',
                 'red': '\033[31m{0}\033[0m',
                 'title': '\033[30;42m{0}\033[0m',
                 'info': '\033[32m{0}\033[0m'}
    msg = color_msg.get(color, 'red').format(msg)
    print(msg)
    if exit:
        time.sleep(2)
        sys.exit()
    return msg


def nmapScan(host, port, arguments='-sV --script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) Chrome/67.0.3396.99 Safari/537.36"',
             sudo=False):
    host, port = str(host), str(port)
    nm = nmap.PortScanner()
    scanResult = nm.scan(host, port, arguments, sudo)

    for k, v in scanResult['scan'][host]['tcp'].items():
        if len(v['cpe']) >= 1:
            if v['cpe'].startswith('cpe:/a'):
                cpe = v['cpe'].split('cpe:/a:')[1]
            elif v['cpe'].startswith('cpe:/o'):
                cpe = v['cpe'].split('cpe:/o:')[1]
            else:
                cpe = v['cpe']

            if len(v['extrainfo']) >= 1:
                extrainfo = v['extrainfo']
                result = "[*] [{}] {:<5} => [{}], [({}), ('extrainfo',{})]".format(v['state'], k, v['name'], cpe, extrainfo)
            else:
                result = "[*] [{}] {:<5} => [{}], [({})]".format(v['state'], k, v['name'], cpe)
        else:
            result = "[*] [{}] {:<5} => [{}]".format(v['state'], k, v['name'])

        if v['state'] == 'open':
            color_print(result, 'yellow')
        else:
            color_print(result, 'red')


def masscanScan(target_ip, target_ports='1-65535'):
    if target_ip:
        custom_port_list = []
        command = 'masscan -p {} {} --rate=1000'.format(target_ports, target_ip)
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while child.poll() is None:
            output = child.stdout.readline()
            tg_port = re.search('Discovered open port (?P<target_port>.*)/tcp on (?:.*)', output)
            if tg_port is not None:
                lock.acquire()
                if degMode:
                    color_print(output.strip(), 'green')
                custom_port_list.append(tg_port.groups()[0])
                lock.release()
            foundNumber = re.findall(r'found=(\d{1,5})', output)
            if foundNumber:
                if int(foundNumber[-1]) > int(limitNum):
                    os.kill(child.pid, 9)
                    # 59.111.14.159
                    color_print('疑似有防火墙!存活端口' + str(foundNumber[-1]) + '个', 'red', True)
    else:
        color_print('请指定一个ip地址!', 'red', True)
    custom_port_list = [int(i) for i in custom_port_list]
    custom_port_list = sorted(custom_port_list)

    _ = ','.join(str(i) for i in custom_port_list)

    color_print('[*] Port: {}'.format(_), 'yellow')

    if len(custom_port_list) < 1:
        color_print('端口扫描失败, 请手动检查是否有防火墙!', 'red', True)
    return _


if __name__ == '__main__':
    # python test.py -p80-90,111,3308,3389,8080-9000,22222 -v --ip 192.168.2.168
    parser = ArgumentParser(add_help=True, description='Port scan tool..')
    parser.add_argument('--ip', dest='ip', nargs='?', type=str, help="Example: 192.168.0.105")
    parser.add_argument('-p', nargs='?', type=str, default='1-65535', help="Example: 80    80-89    80,443,3306,8080-8090")
    parser.add_argument('-v', action='store_true')
    args = parser.parse_args()

    limitNum = 80

    lock = threading.Lock()
    custom_port_list = None

    startTime = time.strftime("%X")

    if args.ip:
        target_ip = args.ip
        target_ports = args.p
        degMode = args.v

        color_print('[{}] Started'.format(startTime), 'yellow')
        color_print('[*] IP: {}'.format(target_ip), 'yellow')

        custom_port_list = masscanScan(target_ip, target_ports)

        if custom_port_list is not None:
            nmapScan(target_ip, custom_port_list)

        endTime = time.strftime('%X')
        color_print('[{}] Completeed'.format(endTime), 'yellow')
