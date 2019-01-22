#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import time
bathdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(bathdir)
sys.path.insert(0, bathdir)
from common import ssh_login_WAF
import requests
import unittest
import HTMLTestRunner
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class RpmTest():
    lws=ssh_login_WAF.LoginWAFSystem()
    build_number_need_test=lws.getBuildNumberNeedTest()
    build_need_test='/root/' + 'zyWAF-' + build_number_need_test + '.centos7.x86_64.rpm'
    def boosh(self):
        general_value = dict(self.lws.readConfigfile('Waf_General'))
        if 'WebServerName' in general_value:
            v_WebServerName = general_value.get('WebServerName')
        else:
            print('ERROR: No WebServerName in parameter list , this testcase will be exit.')
            exit()
        if 'HostNames' in general_value:
            v_HostNames = general_value.get('HostNames').split(',')
        else:
            print('ERROR: No HostNames in parameter list , this testcase will be exit.')
            exit()
        v_WebServerPort = general_value.get('WebServerPort', 80)
        v_ListenPort = general_value.get('ListenPort', 80)
        v_BindIP = general_value.get('BindIP', None)
        v_ListenIP = general_value.get('ListenIP', None)
        v_Bypass = general_value.get('Bypass', False)
        if (v_BindIP == 'None' or v_BindIP == ''):
            v_BindIP = None
        if (v_ListenIP == 'None' or v_ListenIP == ''):
            v_ListenIP = None
        post_data = {"ListenPort": v_ListenPort, "WebServerName": v_WebServerName, "WebServerPort": v_WebServerPort,
                     "BindIP": v_BindIP, "HostNames": v_HostNames, "ListenIP": v_ListenIP, "Bypass": v_Bypass}
        print('post_data:%s' %post_data)
if __name__=='__main__':
    aa=RpmTest()
    aa.boosh()
