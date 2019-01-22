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
#from nose_parameterized import parameterized
#import unittest
#import HTMLTestRunner
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#@parameterized.expand(['Passive', 'Active'])
class Advanced():
    instance_loginWaf=ssh_login_WAF.LoginWAFSystem()
    waf_ip = ssh_login_WAF.readConfigfile('WAF_IP')
    ssh_username, ssh_password = ssh_login_WAF.readConfigfile('WAF_SSH_Login_Info')
    ui_username, ui_password = ssh_login_WAF.readConfigfile('WAF_UI_Login_Info')
    waf_general_conf = ssh_login_WAF.readConfigfile('WAF_General')
    instance_wafEasySetup = ssh_login_WAF.ConfigWafByAPI(waf_ip, ui_username, ui_password, waf_general_conf)
    instance_actionOnClient = ssh_login_WAF.ActionOnClient()

    def testProtectionMode(self,mode):
        case_status = ''
        mode_post_data = {}
        if mode == 'Passive':
            mode_post_data = {"PassiveMode": True}
        elif mode == 'Active':
            mode_post_data = {"PassiveMode": False}
        else:
            print('ERROR: Cannot recognize protection mode, this case will be failed.')
            return
        try:
            mode_response = requests.post('https://%s:8020/API/2.0/Properties/Advanced' % self.waf_ip, json=mode_post_data,
                                      auth=(self.ui_username, self.ui_password), verify=False)
        except requests.exceptions.ConnectionError as e:
            print(e)
        time.sleep(5)
        if mode_response.status_code == 202 or 304:
            self.instance_loginWaf.stopAndStartWafProcess()
            time.sleep(5)
            for new_host_name in self.waf_general_conf.get('HostNames'):
                self.instance_actionOnClient.addHosts(new_host_name, self.waf_ip)
            request_url = 'http://' + self.waf_general_conf.get('HostNames')[0] + '/rest/webResources/1.0/resources'
            try:
                mode_get_response = requests.get(request_url, verify=False)
            except Exception as e:
                print(e)
            if mode == 'Passive' and mode_get_response.status_code == 200:
                case_status = 'OK'
                print('post code=202,passive mode,get,mode_get_response.status_code: %s' % mode_get_response.status_code)
            elif mode == 'Active' and mode_get_response.status_code == 403:
                case_status = 'OK'
                print('post code =202, active mode,get,mode_get_response.status_code:%s' % mode_get_response.status_code)
            else:
                case_status = 'FAIL'
                print('post code =202,not passive + get status 200,not active + get status 403')
        elif mode_response.status_code == 200 or 304:
            # need to check protect mode can take effect
            for new_host_name in self.waf_general_conf.get('HostNames'):
                self.instance_actionOnClient.addHosts(new_host_name, self.waf_ip)
            request_url = 'http://' + self.waf_general_conf.get('HostNames')[0] + '/rest/webResources/1.0/resources'
            try:
                mode_get_response = requests.get(request_url, verify=False)
            except Exception as e:
                print(e)
            if mode == 'Passive' and mode_get_response.status_code == 200:
                case_status = 'OK'
                print('post code=200,passive mode,get,mode_get_response.status_code: %s' % mode_get_response.status_code)
            elif mode == 'Active' and mode_get_response.status_code == 403:
                case_status = 'OK'
                print('post code =200,active mode,get,mode_get_response.status_code:%s' % mode_get_response.status_code)
            else:
                case_status = 'FAIL'
                print('post code =200, not passive + get status 200,not active + get status 403')
        else:
            case_status = 'FAIL'
            print('post fail, not 202 or 200 or 304')

if __name__ == '__main__':
    aa = Advanced()
    aa.testProtectionMode('Passive')
    aa.testProtectionMode('Active')