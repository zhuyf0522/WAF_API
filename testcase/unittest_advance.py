#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
bathdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(bathdir)
sys.path.insert(0, bathdir)
from common import ssh_login_WAF
import requests
import time
import unittest
from nose_parameterized import parameterized, param
from scapy.all import *
import HTMLTestRunner
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Advanced(unittest.TestCase):
    instance_loginWaf = ssh_login_WAF.LoginWAFSystem()
    waf_ip = ssh_login_WAF.readConfigfile('WAF_IP')
    ssh_username, ssh_password = ssh_login_WAF.readConfigfile('WAF_SSH_Login_Info')
    ui_username, ui_password = ssh_login_WAF.readConfigfile('WAF_UI_Login_Info')
    waf_general_conf = ssh_login_WAF.readConfigfile('WAF_General')
    instance_wafEasySetup = ssh_login_WAF.ConfigWafByAPI(waf_ip, ui_username, ui_password, waf_general_conf)
    instance_actionOnClient = ssh_login_WAF.ActionOnClient()

    @classmethod
    def setUpClass(cls):  # this method will remove old WAF, intall a new version waf
        cls.instance_loginWaf.reInstallWAF()
        cls.instance_loginWaf.changeWAFPassword()
        #cls.instance_wafEasySetup.wafEasySetup()

    @unittest.skipIf(waf_general_conf.get('WebServerName') != '10.2.178.131', reason='waf ip should be 10.2.178.131,case use jira on this os')
    #@parameterized.expand(['Passive', 'Active'])
    def AtestProtectionMode(self, mode):
        case_status = ''
        mode_post_data={}
        if mode == 'Passive':
            mode_post_data = {"PassiveMode": True}
        elif mode == 'Active':
            mode_post_data = {"PassiveMode": False}
        else:
            print('ERROR: Cannot recognize protection mode, this case will be failed.')
            self.assertEqual(case_status,'OK')
            return
        try:
            mode_response = requests.post('https://%s:8020/API/2.0/Properties/Advanced' % self.waf_ip, json=mode_post_data,
                                  auth=(self.ui_username, self.ui_password), verify=False)
        except requests.exceptions.ConnectionError as e:
            print(e)
        time.sleep(5)
        if mode_response.status_code in [202 , 304]:
            self.instance_loginWaf.stopAndStartWafProcess()
            time.sleep(5)
            for new_host_name in self.waf_general_conf.get('HostNames'):
                self.instance_actionOnClient.addHosts(new_host_name,self.waf_ip)
            request_url = 'http://' + self.waf_general_conf.get('HostNames')[0] + '/rest/webResources/1.0/resources'
            try:
                mode_get_response = requests.get(request_url,verify=False)
            except requests.exceptions.ConnectionError as e:
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
        elif mode_response.status_code in [200 ,304]:
            # need to check protect mode can take effect
            for new_host_name in self.waf_general_conf.get('HostNames'):
                self.instance_actionOnClient.addHosts(new_host_name,self.waf_ip)
            request_url = 'http://' + self.waf_general_conf.get('HostNames')[0] + '/rest/webResources/1.0/resources'
            try:
                mode_get_response = requests.get(request_url,verify=False)
            except ConnectionResetError as e:
                print(e)
                raise
                pass
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
        self.assertEqual(case_status,'OK',msg='change to %s mode  failed, cannot work' %mode)


    def AtestHttpRedirectHttps(self):
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        post_data = {"RedirectHTTPS": True}
        post_URL = 'https://%s:8020/API/2.0/Properties/Advanced' % self.waf_ip
        get_URL = 'http://' + waf_config.get('HostNames')[0]
        try:
            post_response = requests.post(post_URL,json=post_data,auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code == 200:
                get_response = requests.get(get_URL,allow_redirects=False)
                #status_code should be 302, location in header should be https://....
                if get_response.status_code == 302 and get_response.headers['Location'] == 'https://' + waf_config.get('HostNames')[0] + '/':
                    case_status = 'OK'
                else:
                    case_status = 'FAIL'
            else:
                print('Case failed. post_response_status_code=%s, not 200' % post_response.status_code)
                case_status = 'FAIL'
        except requests.exceptions.ConnectionError as e:
            print(e)
            case_status = 'FAIL'
        self.assertEqual(case_status,'OK',msg='post_response_status_code=%s,get_response_status_code=%s' %(post_response.status_code,get_response.status_code))

    @parameterized.expand([([{"XForwardedFor": True, "AddXRealIP": True}]),([{"XForwardedFor": True, "AddXForwardedFor": True}]),
                           ([{"XForwardedFor": True,"AddXForwardedProto": True}]),
                           ([{"XForwardedFor": True,"AddXHeaderEnable": True, "AddXHeaderName": "zyXFF"}]),
                           ([{"XForwardedFor": True,"ClientIPXHeaderValue": "zywaf"}])])
    #data = {"XForwardedFor": True, "AddXRealIP": True}
    #@parameterized.expand([([data])])
    def testAddXFF(self,post_data):
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        print("post_data:",post_data)
        # 1. enable XFF, send a post to enable
        # 2. ssh to local host , run tcpdump to capture packets and put it in /home/jason/automation/waf/packet
        # 3. send a request to web server through
        # 4. stop tcpdump , use scapy to analysis http header in captured packets , check XFF value
        #post_data = {"XForwardedFor": True, "AddXForwardedFor": True}
        post_URL = 'https://%s:8020/API/2.0/Properties/Advanced' % self.waf_ip
        header = {"zywaf": "10.2.8.88"}
        proto = ssh_login_WAF.readConfigfile('Web_Server_Info', 'protocol')
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0],self.waf_ip)
        case_status = 'FAIL'
        try:
            post_response = requests.post(post_URL,json=post_data,auth=(self.ui_username, self.ui_password),verify=False)
            if post_response.status_code in [200,304]:
                parameters_info = {'local': False,
                                'hostIP': ssh_login_WAF.readConfigfile('Web_Server_Info', 'host'),
                                'user': ssh_login_WAF.readConfigfile('Web_Server_Info', 'ssh_username'),
                                'password': ssh_login_WAF.readConfigfile('Web_Server_Info', 'ssh_password')}
                int_name = self.instance_loginWaf.getHostInterface(**parameters_info)
                remote_pcap_file = ssh_login_WAF.readConfigfile('Pcap_Path','remote_path') + 'xff.pcap'
                cmd = 'nohup tcpdump -i %s -nn -s 0 -c 50 host %s -w %s > /dev/null 2>&1 &' %(int_name,self.waf_ip,remote_pcap_file)
                parameters_info.update({'command': cmd})
                self.instance_loginWaf.connectAndExeccommand(**parameters_info)
                time.sleep(3)
                if post_data.get("ClientIPXHeaderValue"):
                    request_response = requests.get(proto + '://' + waf_config.get('HostNames')[0], headers=header,verify=False)
                else:
                    request_response = requests.get(proto + '://' + waf_config.get('HostNames')[0],verify=False)
                if request_response.status_code == 200:
                    original_ip = search_value = None
                    time.sleep(10)
                    parameters_info['command'] = 'pidof tcpdump'
                    tcpdump_pid = self.instance_loginWaf.connectAndExeccommand(**parameters_info)
                    if tcpdump_pid:
                        print("INFO: Begin to kill tcpdump process.")
                        parameters_info['command'] = 'kill -2 %s' % tcpdump_pid
                        self.instance_loginWaf.connectAndExeccommand(**parameters_info)
                    parameters_info.update({'type': 'remote_read','file_name': 'xff.pcap'})
                    self.instance_loginWaf.sftpRemoteCopy(**parameters_info)
                    print("INFO: Copy complete. ")
                    cmd = "find %s -name xff.pcap -exec rm -rf {} \;" % ssh_login_WAF.readConfigfile("Pcap_Path","remote_path")
                    parameters_info["command"] = cmd
                    self.instance_loginWaf.connectAndExeccommand(**parameters_info)
                    pcap_file = ssh_login_WAF.readConfigfile('Pcap_Path','local_path') + 'xff.pcap'
                    if post_data.get("AddXForwardedFor"):
                        search_item = "X-Forwarded-For"
                    elif post_data.get("AddXRealIP"):
                        search_item = "X-Real-IP"
                    elif post_data.get("AddXForwardedProto"):
                        search_item = "X-Forwarded-Proto"
                    elif post_data.get("AddXHeaderName"):
                        search_item = post_data.get("AddXHeaderName")
                    elif post_data.get("ClientIPXHeaderValue"):
                        original_ip = post_data.get("ClientIPXHeaderValue")
                    if original_ip:
                        search_value = ssh_login_WAF.getHttpHeader(pcap_file, original_ip)
                        if search_value == header.get("zywaf"):
                            case_status = "OK"
                    elif search_item:
                        if search_item == "AddXForwardedProto":
                            search_value = ssh_login_WAF.getHttpHeader(pcap_file, search_item)
                            if search_value == proto:
                                case_status = "OK"
                        else:
                            search_value = ssh_login_WAF.getHttpHeader(pcap_file,search_item)
                            if search_value == ssh_login_WAF.getHostIP():
                                case_status = 'OK'
        except Exception as e:
            print(e)
            case_status = 'FAIL'
        self.assertEqual(case_status,'OK',msg='post_status_code=%s,get_status_code=%s,x_ff_ip=%s' %(post_response.status_code,request_response.status_code,search_value))
        time.sleep(30)


    '''
    @classmethod
    def tearDownClass(cls):
       cls.instance_loginWaf.removeWAF() 
    '''


if __name__=='__main__':
    suite=unittest.TestSuite()
    suite.addTest(unittest.makeSuite(Advanced))
#    fw= open('verify_version.html','wb')
#    runner= HTMLTestRunner.HTMLTestRunner(stream=fw,title='Unittest Result',description='verify version API')
    runner=unittest.TextTestRunner(verbosity=2)
    runner.run(suite)

