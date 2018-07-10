# Python端口指纹识别   
[![python27](https://img.shields.io/badge/python-2.7.10-brightgreen.svg?style=plastic)](https://www.python.org/)   

### 0x00 前言
masscan 结合 nmap 进行端口扫描与端口指纹识别

### 0x01 介绍
* 1.先调用masscan扫描端口，正则提取出端口   
* 2.调用nmap进行端口指纹识别   
* ~~3.再调用对应服务的未授权和弱口令检测插件~~   

默认会调用masscan扫描所有端口。    


### 0x03 使用     
##### Usage:   
```
python portScan.py --ip 192.168.2.168    
python portScan.py --ip 192.168.2.168 -v    
python portScan.py -p80-90,111,3308,3389,8080-9000,22222 -v --ip 192.168.2.168
```
##### Example:   
![example](result.png)   


### TODO
* 支持多ip或ip段检测
* 支持弱口令和未授权检测