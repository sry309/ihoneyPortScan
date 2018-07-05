# -*- coding: utf-8 -*-
import random
import struct
import socket
import time
import select
import sys
import os
import re
import subprocess
import threading
import queue

_https = False
try:
    import ssl

    _https = True
except:
    pass


def color_print(msg, color='red', exit=False):
    color_msg = {'blue': '\033[36m{0}\033[0m',
                 'green': '\033[32m{0}\033[0m',
                 'yellow': '\033[33m{0}\033[0m',
                 'red': '\033[31m{0}\033[0m',
                 'title': '\033[30;42m{0}\033[0m',
                 'info': '\033[32m{0}\033[0m'}
    msg = color_msg.get(color, 'red').format(msg)
    print(msg)
    if exit:
        time.sleep(2)
        sys.exit()
    return msg


class mssqlServerObj(object):
    def __init__(self):
        self.packetno = 0
        self.length = 0
        self.size = 0
        self.cli_version = 7
        self.cli_pid = 0
        self.conn_id = 0
        self.options_1 = 160
        self.options_2 = 3
        self.sqltype_flag = 0
        self.reserved_flag = 0
        self.time_zone = 0
        self.collation = 0
        self.version = 1895825409
        self.client = "Nmap"
        self.username = None
        self.password = None
        self.app = "Nmap NSE"
        self.server = "DUMMY"
        self.library = "mssql.lua"
        self.locale = ""
        self.database = "tempdb"
        self.MAC = "\x00\x00\x00\x00\x00\x00"

    def widechar(self, ch):
        return ch + "."

    def widestring(self, s):
        return "".join(map(self.widechar, s))

    def encryptpass(self, s):
        tmpLen = 23130
        passdata = ""
        for tmp in s:
            tmp = ord(tmp) ^ tmpLen
            passdata += struct.pack("H", tmp >> 4 & 3855 | tmp << 4 & 61680)

        return passdata

    def to_string(self):
        lenData = 86
        self.cli_pid = random.randint(1, 100000)

        self.length = lenData + 2 * (
                len(self.client) + len(self.username) + len(self.password) + len(self.app) + len(self.server) + len(
            self.library) + len(self.database))

        tcpData = struct.pack("<IIIIII", self.length, self.version, self.size, self.cli_version, self.cli_pid,
                              self.conn_id)
        tcpData += struct.pack("BBBB", self.options_1, self.options_2, self.sqltype_flag, self.reserved_flag)
        tcpData += struct.pack("<II", self.time_zone, self.collation)
        tcpData += struct.pack("<HH", lenData, len(self.client))
        lenData += len(self.client) * 2
        tcpData += struct.pack("<HH", lenData, len(self.username))
        lenData += len(self.username) * 2
        tcpData += struct.pack("<HH", lenData, len(self.password))
        lenData += len(self.password) * 2
        tcpData += struct.pack("<HH", lenData, len(self.app))
        lenData += len(self.app) * 2
        tcpData += struct.pack("<HH", lenData, len(self.server))
        lenData += len(self.server) * 2
        tcpData += struct.pack("<HH", 0, 0)
        tcpData += struct.pack("<HH", lenData, len(self.library))
        lenData += len(self.library) * 2
        tcpData += struct.pack("<HH", lenData, len(self.locale))
        lenData += len(self.locale) * 2
        tcpData += struct.pack("<HH", lenData, len(self.database))
        lenData += len(self.database) * 2
        tcpData += self.MAC
        tcpData += struct.pack("<H", lenData)
        tcpData += struct.pack("<H", 0)
        tcpData += struct.pack("<H", self.length)
        tcpData += struct.pack("<H", 0)
        tcpData += self.widestring(self.client)
        tcpData += self.widestring(self.username)
        tcpData += self.encryptpass(self.password)
        tcpData += self.widestring(self.app)
        tcpData += self.widestring(self.server)
        tcpData += self.widestring(self.library)
        tcpData += self.widestring(self.locale)
        tcpData += self.widestring(self.database)
        return tcpData

    def login(self, server, username, password, port, timeout):
        self.username = username
        self.password = password
        self.server = server
        data = self.to_string()
        datalen = len(data) + 8
        int_1 = 1
        int_0_1 = 0
        int_0 = 0
        self.packetno += 1
        int_16 = 16
        sockData = struct.pack(">BBHHBB%ds" % len(data), int_16, int_1, datalen, int_0_1, self.packetno,
                               int_0, data)
        socketObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketObj.settimeout(timeout)
        socketObj.connect((server, port))
        socketObj.send(sockData)
        read_N = ""
        Ii1I = 0
        int_1 = 0
        readOk = False
        Ooo = ""
        while True:
            if len(read_N) - Ii1I < 4:
                read = socketObj.recv(4)
                if len(read) > 0:
                    read_N += read
                    readOk = True
                else:
                    return None, "Fail to receive packet from MSSQL server"
            int_16, int_1, iI1 = struct.unpack_from(">BBH", read_N, Ii1I)
            Ii1I += 4
            if int_16 != 4:
                return None, "Server returned invalid packet"
            ii1I1i1I = iI1 - (len(read_N) - Ii1I + 4)
            if ii1I1i1I > 0:
                read = socketObj.recv(ii1I1i1I)
                if len(read) > 0:
                    read_N += read
                else:
                    return None, "Fail to receive packet from MSSQL server"
            # id, tag, version, count
            int_0_1, OOoo0O0, int_0, read = struct.unpack_from(">Hcc%ds" % (iI1 - 8), read_N, Ii1I)
            Ooo += read
            Ii1I += 4 + (iI1 - 8)
            if int_1 == 1:
                break

        socketObj.close()
        if not readOk:
            return None, "Unkown error"
        O0ooOooooO, = struct.unpack_from("B", Ooo, 0)
        if O0ooOooooO == 170:
            return False
        else:
            if O0ooOooooO == 227:
                return True
            return None, "Token ERROR"


class myThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def mssqlServer(self, arg):
        host, port = arg
        serverInfo = None
        try:
            mssql = mssqlServerObj()
            if not mssql.login(host, "sa", "thispassneverused$$$", port, 10):
                serverInfo = "mssql"
        except:
            pass

        return serverInfo

    def SSHServer(self, arg):
        serverInfo = None
        serverHeader = None
        host, port = arg
        try:
            socketObj = sockHttp(host, port, 10)
            read = socketObj.recv(1024)
            serverHeader = read.strip()
            if read.find("SSH-") != -1:
                serverInfo = "ssh"
            elif read.find("220 ") == 0:
                if port == 25:
                    serverInfo = "smtp"
                else:
                    serverInfo = "ftp"
            elif read.find("MySQL") != -1 or read.find("mysqladmin") != -1 or read.find('mysql_native_password') != -1:
                serverInfo = "mysql"
            elif read.find("RFB ") == 0:
                serverInfo = "vnc"
            elif len(read) > 5:
                read_regex = read.find(".", 5)
                if read_regex != -1:
                    serverHeader = read[5:read_regex].decode("latin1")
                    if len(serverHeader) > 2 and serverHeader[1] == ".":
                        serverInfo = "mysql"
            socketObj.close()
        except Exception as i1:
            pass

        if serverHeader:
            serverHeader = "".join(map(lambda x: (x if ord(x) >= 32 and ord(x) <= 126 else "\\x%02X" % ord(x)), serverHeader))
        return serverInfo, serverHeader

    def jdwpServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        jdwpServerInfo = "JDWP-Handshake"
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(jdwpServerInfo)
            read = socketObj.recv(15)
            if "JDWP-Handshake" in read:
                serverInfo = "jdwp"
        except Exception as i1:
            pass
        return serverInfo, serverHeader

    def rdpServer(self, arg):
        serverInfo = None
        host, port = arg
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send("\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00")
            if socketObj.recv(2) == "\x03\x00":
                serverInfo = "rdp"
            socketObj.close()
        except Exception as i1:
            pass

        return serverInfo

    def httpServer(self, arg):
        serverInfo = None
        serverHeader = None
        host, port = arg
        ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36'

        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n" % (host, ua))
            read = socketObj.recv(1024)
            if read.find("HTTP/1.") == 0 or read.lower().find("<html") > 0:
                if "access MongoDB" not in read:
                    import re
                    serverInfo = "www"
                    if port == 443:
                        serverInfo = "ssl"
                    read_regex = re.findall("^(Server|X\-[\w\-]*):\s+([^\r\n]+)", read, re.M | re.I)
                    if read_regex:
                        serverHeader = str(read_regex)
            socketObj.close()
        except Exception:
            pass

        return serverInfo, serverHeader

    def rsyncServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        header = {"MagicHeader": "@RSYNCD:",
                  "HeaderVersion": " 30.0"}
        data = struct.pack("!8s5ss", header["MagicHeader"], header["HeaderVersion"], "\n")
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(data)
            read = socketObj.recv(14)
            if "RSYNCD" in read:
                serverInfo = "rsync"
                serverHeader = read.strip()
        except Exception as i1:
            pass

        return serverInfo, serverHeader

    def memcachedServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        data = "version\n"
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(data)
            read = socketObj.recv(1024)
            if "VERSION" in read:
                serverInfo = "memcached"
                serverHeader = read.strip()
        except Exception as i1:
            pass

        return (serverInfo, serverHeader)

    def smbServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        smbData = ("00000045ff534d42720000000000000800000000000000000000000" + \
                   "0ffff000000000000002200024e54204c4d20302e31320002534d42" + \
                   "20322e3030320002534d4220322e3f3f3f00".decode("hex"),)
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(smbData[0])
            read = socketObj.recv(1024)
            if read[0] == '''.''' and "SMB" in read:
                serverInfo = "smb"
        except Exception as i1:
            pass

        return serverInfo, serverHeader

    def mongodbServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        mongodbHeader = "360000000100000000000000d40700000400000061646d696e" + \
                        "2e24636d640000000000ffffffff0f0000001070696e670001" + \
                        "00000000".decode("hex")
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(mongodbHeader)
            read = socketObj.recv(1024)

            if "\x11\x00\x00\x00\x01\x6f\x6b\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00" in read:
                serverInfo = "mongodb"

        except Exception as i1:
            pass

        return (serverInfo, serverHeader)

    def postgresServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None

        postgresqlInfo = "\x00\x00\x00\x52\x00\x03\x00\x00\x75\x73\x65\x72\x00\x70\x6f\x73\x74\x67\x72\x65\x73\x00\x64\x61\x74\x61\x62\x61\x73\x65\x00\x70\x6f\x73\x74\x67\x72\x65\x73\x00\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x5f\x6e\x61\x6d\x65\x00\x70\x67\x41\x64\x6d\x69\x6e\x20\x49\x49\x49\x20\x2d\x20\xe6\xb5\x8f\xe8\xa7\x88\xe5\x99\xa8\x00\x00"

        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(postgresqlInfo)
            read = socketObj.recv(15)
            if read.startswith("\x52\x00\x00\x00") or read.startswith("\x45\x00\x00\x00"):
                serverInfo = "postgresql"

        except Exception as i1:
            pass

        return serverInfo, serverHeader

    def redisServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        tcpData = "*1\r\n$4\r\ninfo\r\n"
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(tcpData)
            read = socketObj.recv(200)
            if "redis_version" in read:
                serverInfo = "redis"
                ver = read.index("redis_version")
                serverHeader = read[ver + 14:ver + 20]
            elif "ERR operation not permitted" in read:
                serverInfo = "redis"
            elif "ERR wrong number" in read:
                serverInfo = "redis"
            elif "AUTH Authentication required" in read:
                serverInfo = "redis"
        except Exception as e:
            pass

        return serverInfo, serverHeader

    def ldapServer(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = None
        tcpData = "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x02\x04\x00\x80\x00"
        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(tcpData)
            read = socketObj.recv(200)
            if read[4] == "":
                serverInfo = "ldap"
                if read[9] == '''.''':
                    serverHeader = "ldapv2"
                elif read[9] == "":
                    if "LDAPv3" in read[14:]:
                        serverHeader = "ldapv3"
                    else:
                        serverHeader = "ldapv1"
        except Exception as i1:
            pass

        return serverInfo, serverHeader

    def socks5Server(self, arg):
        host, port = arg
        serverInfo = None
        serverHeader = ""
        tcpData = "\x05\xff"
        for iii in range(255):
            tcpData += struct.pack("!B", iii)

        try:
            socketObj = sockHttp(host, port, 10)
            socketObj.send(tcpData)
            read = socketObj.recv(1024)
            if len(read) == 2 and read[0] == "":
                serverInfo = "socks5"
                reTcpData = struct.unpack("!B", read[1])[0]
                if reTcpData == 0:
                    serverHeader = "NO AUTHENTICATION REQUIRED"
                elif reTcpData == 1:
                    serverHeader = "GSSAPI"
                elif reTcpData == 2:
                    serverHeader = "USERNAME/PASSWORD"
                elif reTcpData >= 3 and reTcpData <= 127:
                    serverHeader = "IANA ASSIGNED"
                elif reTcpData >= 128 and reTcpData <= 254:
                    serverHeader = "RESERVED FOR PRIVATE METHODS"
                elif reTcpData == "0xff":
                    serverHeader = "NO ACCEPTABLE METHODS"
                else:
                    serverHeader = ""
        except Exception as i1:
            pass

        return serverInfo, serverHeader

    def __auth(self, func_hp):
        scan_func = func_hp[0]
        host_port = func_hp[1]
        # print(22, scan_func, host_port)
        if scan_func == 'httpServer':
            serverResult = self.httpServer(host_port)
        elif scan_func == 'SSHServer':
            serverResult = self.SSHServer(host_port)
        elif scan_func == 'rdpServer':
            serverResult = self.rdpServer(host_port)
        elif scan_func == 'mssqlServer':
            serverResult = self.mssqlServer(host_port)
        elif scan_func == 'rsyncServer':
            serverResult = self.rsyncServer(host_port)
        elif scan_func == 'memcachedServer':
            serverResult = self.memcachedServer(host_port)
        elif scan_func == 'smbServer':
            serverResult = self.smbServer(host_port)
        elif scan_func == 'mongodbServer':
            serverResult = self.mongodbServer(host_port)
        elif scan_func == 'jdwpServer':
            serverResult = self.jdwpServer(host_port)
        elif scan_func == 'redisServer':
            serverResult = self.redisServer(host_port)
        elif scan_func == 'postgresServer':
            serverResult = self.postgresServer(host_port)
        elif scan_func == 'socks5Server':
            serverResult = self.socks5Server(host_port)
        elif scan_func == 'ldapServer':
            serverResult = self.ldapServer(host_port)

        if isinstance(serverResult, str):
            lock.acquire()
            color_print("[*] %d => [%s]; Ver => %s" % (host_port[1], serverResult, ''), 'green')
            lock.release()
        elif isinstance(serverResult, tuple) and isinstance(serverResult[0], str):
            lock.acquire()
            color_print("[*] %d => [%s]; Ver => %s" % (host_port[1], serverResult[0], serverResult[1] if serverResult[1] else ""), 'green')
            lock.release()

    def run(self):
        while not self.queue.empty():
            func_hostport = self.queue.get()
            try:
                self.__auth(func_hostport)
            except:
                continue


def sockHttp(host, port, timeout=5):
    socketObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if port == 443:
        if not _https:
            raise Exception('Not support SSL')
        try:
            socketObj = ssl.wrap_socket(socketObj, ssl_version=ssl.PROTOCOL_TLSv1)
        except ssl.SSLError:
            socketObj = ssl.wrap_socket(socketObj, ssl_version=ssl.PROTOL_SSLv23)

    socketObj.settimeout(timeout)
    socketObj.connect((host, port))
    return socketObj


def sockSend(host, port, timeout):
    try:
        socketObj = sockHttp(host, port, timeout)
        try:
            socketObj.settimeout(0.5)
            socketObj.recv(0)
        except socket.timeout:
            pass

        socketObj.close()
        return True
    except Exception as i1:
        pass

    return False


def scanPort(host, ports, timeout):
    portList = []
    sockList = set()
    while len(ports):
        socketObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketObj.setblocking(0)
        socketObj.connect_ex((host, ports.pop()))
        sockList.add(socketObj)
        if len(sockList) < 200 and len(ports) > 0:
            continue
        start_time = time.time()
        try:
            while True:
                # readable,writeable,exceptional
                readable, writeable, exceptional = select.select([], sockList,
                                                                 [], 0.5)
                if len(writeable) > 0:
                    for socketObj in writeable:
                        strtus = socketObj.getsockopt(socket.SOL_SOCKET,
                                                      socket.SO_ERROR)
                        if strtus == 0:
                            host, port = socketObj.getpeername()
                            portList.append(port)
                        socketObj.close()

                    sockList = sockList - set(writeable)
                if time.time() - start_time > timeout:
                    break
        except:
            pass

        sockList = set()

    portList.sort()
    return portList


def assign(service, arg):
    if service != "ip":
        return
    else:
        return (True, arg)


def audit(arg):
    host = arg
    checkServer = [([80, 8080, 81, 443], 'httpServer'),
                   ([22, 21, 25, 3306, 5900], 'SSHServer'),
                   ([3389], 'rdpServer'),
                   ([1433], 'mssqlServer'),
                   ([873], 'rsyncServer'),
                   ([11211], 'memcachedServer'),
                   ([445], 'smbServer'),
                   ([27017], 'mongodbServer'),
                   ([3999, 5000, 5005, 8000, 8453, 8787, 8788, 8789, 9001, 9871, 18000], 'jdwpServer'),
                   ([6379], 'redisServer'),
                   ([5432], 'postgresServer'),
                   ([1080], 'socks5Server'),
                   ([389, 636], 'ldapServer')
                   ]
    ports = []
    linkPorts = []
    for port, getSer in checkServer:
        linkPorts += port

    ports += linkPorts

    if not (sockSend(host, 190, 5) or sockSend(host, 86, 5)):
        if custom_port_list is not None:
            ports += custom_port_list
        # else:
        #     ports += port_list()
        ports = set(ports)

    linkPort = []
    linkPort = scanPort(arg, ports, 10)
    if linkPort:
        if len(linkPort) < 50:
            lock.acquire()
            color_print("[*] TCP: " + repr(linkPort), 'green')
            lock.release()
        else:
            linkPort = linkPorts
    if 80 not in linkPort:
        linkPort.append(80)

    targetList = []
    for port, serverScanObj in checkServer:
        port = list(set(port + linkPort))
        port.sort()
        targetList.append((port, serverScanObj))

    okPort = []
    q = queue.Queue()
    for linkPort, serverScanObj in targetList:
        for port in linkPort:
            if port in okPort:
                continue
            q.put((serverScanObj, (host, port)))
    threadl = [myThread(q) for _ in range(threadnum)]
    for t in threadl:
        t.start()

    for t in threadl:
        t.join()


if __name__ == '__main__':
    lock = threading.Lock()
    custom_port_list = None
    target_ip = sys.argv[1]
    threadnum = 20
    limitNum = 80
    if target_ip:
        color_print('-' * 60, 'blue')
        color_print('[*] IP: %s' % target_ip, 'green')
        custom_port_list = []
        command = 'masscan -p 1-65535 {} --rate=1000'.format(target_ip)
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while child.poll() is None:
            output = child.stdout.readline()
            tg_port = re.search('Discovered open port (?P<target_port>.*)/tcp on (?:.*)', output)
            if tg_port is not None:
                lock.acquire()
                color_print(output.strip(), 'blue')
                custom_port_list.append(tg_port.groups()[0])
                lock.release()
            foundNumber = re.findall(r'found=(\d{1,5})', output)
            if foundNumber:
                if int(foundNumber[-1]) > int(limitNum):
                    os.kill(child.pid, 9)
                    # 59.111.14.159
                    color_print('疑似有防火墙!存活端口' + str(foundNumber[-1]) + '个', 'red',True)
    custom_port_list = [int(i) for i in custom_port_list]
    color_print('[*] Port: ' + str(custom_port_list), 'green')
    color_print('-' * 60, 'blue')
    if len(custom_port_list) < 1:
        color_print('端口扫描失败, 请手动检查是否有防火墙!', 'red', True)
    # custom_port_list = [80, 445, 3306, 3389]

    audit(assign("ip", target_ip)[1])
