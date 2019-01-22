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
import HTMLTestRunner
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class wafRegression(unittest.TestCase):
    instance_loginWaf=ssh_login_WAF.LoginWAFSystem()
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
    
    def AtestGetAllVersion(self):
        current_waf_version=requests.get('https://%s:8020/API/2.0/Version' %self.waf_ip,auth=(self.ui_username,self.ui_password),verify=False)
        api_build_number=str(current_waf_version.json()["Major"]) + '.' + str(current_waf_version.json()["Minor"]) + '.' + str(current_waf_version.json()["Revision"]) + '.' + str(current_waf_version.json()["Build"])
        build_number=current_waf_version.json()["Build"]
        version_file_content=self.instance_loginWaf.connectAndExeccommand(command='cat /usr/local/waf/etc/VERSION',ret=True)
        #version_file_content=str(version_file_content,encoding='utf-8')
        #print(version_file_content.split('\n'))
        for item in version_file_content.split('\n'):
            if item.find('MAJOR') !=-1:
                waf_major=item.split('=')[1]
            if item.find('MINOR') !=-1:
                waf_minor=item.split('=')[1]
            if item.find('REVISION') !=-1:
                waf_revision=item.split('=')[1]
            if item.find('BUILD') !=-1:
                waf_build_number=item.split('=')[1]
        backgroud_build_number=str(waf_major) + '.' + str(waf_minor) + '.' + str(waf_revision) + '.' + str(waf_build_number)
        self.assertEqual(api_build_number,backgroud_build_number)

    def AtestWafGeneral(self):
        post_data = self.instance_wafEasySetup.wafEasySetup()
        for new_host_name in post_data.get('HostNames'):
            self.instance_actionOnClient.addHosts(new_host_name, self.waf_ip)
        request_URL = 'http://' + post_data.get('HostNames')[0]
        print(request_URL)
        time.sleep(5)
        try:
            response_get = requests.get(request_URL, verify=False)
        except requests.exceptions as e:
            print(e)
        time.sleep(2)
        for new_host_name in post_data.get('HostNames'):
            reg_test = '.*' + new_host_name
            self.instance_actionOnClient.searchAndDeleteLine(reg_test)
        self.assertEqual(response_get.status_code, 200, msg='ERROR: Response code of get request is not 200')

    def AtestChangeServerIP(self):
        new_webserver_IP = '10.2.178.132'
        case_status = post_response = get_response = None
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        post_data = {'WebServerName': new_webserver_IP}
        request_URL = 'http://' + waf_config.get('HostNames')[0]
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0], self.waf_ip)
        try:
            post_response = requests.post('https://%s:8020/API/2.0/Properties/General' % self.waf_ip, json=post_data,
                                  auth=(self.ui_username, self.ui_password), verify=False)
            time.sleep(2)
            if post_response.status_code == 202:
                self.instance_loginWaf.stopAndStartWafProcess()
                time.sleep(5)
                try:
                    get_response = requests.get(request_URL, verify=False)
                    if get_response.status_code == 200:
                        case_status = 'OK'
                    else:
                        case_status = 'FAIL'
                except requests.exceptions as e:
                    print(e)
                    case_status = 'FAIL'
            else:
                case_status = 'FAIL'
        except requests.exceptions as e:
            print(e)
            case_status = 'FAIL'
        reg_string = '.*' + waf_config.get('HostNames')[0]
        self.instance_actionOnClient.searchAndDeleteLine(reg_string)
        self.assertEqual(case_status,'OK',msg='Case failed.post_response_status_code=%s, get_response_status_code%s' %(post_response.status_code,get_response.status_code))


    def AtestChangeServerPort(self):
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        post_data = {'WebServerPort': '80'}
        case_status = get_response = post_response = None
        request_URL = 'http://' + waf_config.get('HostNames')[0] + ':80/'
        # need to add hosts file to resolve hostname
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0], self.waf_ip)
        try:
            post_response = requests.post('https://%s:8020/API/2.0/Properties/General' % self.waf_ip, json=post_data,
                                          auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code == 202:
                self.instance_loginWaf.stopAndStartWafProcess()
                time.sleep(5)
                try:
                    get_response = requests.get(request_URL,verify=False)
                    if get_response.status_code == 200:
                        case_status = 'OK'
                    else:
                        case_status = 'FAIL'
                except requests.exceptions as e:
                    print(e)
                    case_status = 'FAIL'
            else:
                case_status = 'FAIL'
        except requests.exceptions as e:
            print(e)
            case_status = 'FAIL'
        self.instance_actionOnClient.searchAndDeleteLine('.*' + waf_config.get('HostNames')[0])
        self.assertEqual(case_status,'OK',msg='Case failed, post_status_code=%s,get_status_code=%s' %(post_response.status_code,get_response.status_code))

    def AtestChangeWAFPort(self):
        waf_config=self.instance_wafEasySetup.wafEasySetup()
        post_data = {'ListenPort':'9999'}
        request_URL = 'http://' + waf_config.get('HostNames')[0] + ':9999/'
        case_status = post_response = get_response = None
        # need to add hosts file to resolve hostname
        cmd_list = ['firewall-cmd --permanent --add-port=9999/tcp','firewall-cmd --reload']
        self.instance_loginWaf.connectAndExeccommand(cmd_list)
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0], self.waf_ip)
        try:
            post_response = requests.post('https://%s:8020/API/2.0/Properties/General' % self.waf_ip, json=post_data,auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code == 202:
                self.instance_loginWaf.stopAndStartWafProcess()
                time.sleep(5)
                try:
                    get_response = requests.get(request_URL,verify=False)
                    if get_response.status_code == 200:
                        case_status = 'OK'
                    else:
                        case_status = 'FAIL'
                except requests.exceptions as e:
                    print(e)
                    case_status = 'FAIL'
            else:
                case_status = 'FAIL'
        except requests.exceptions as e:
            print(e)
            case_status = 'FAIL'
        # need to remove firewall rule which add in this case
        self.instance_actionOnClient.searchAndDeleteLine('.*' + waf_config.get('HostNames')[0])
        cmd_list = ['firewall-cmd --permanent --remove-port=9999/tcp','firewall-cmd --reload']
        self.instance_loginWaf.connectAndExeccommand(cmd_list)
        self.assertEqual(case_status,'OK',msg='Case failed. post_status_code=%s,get_status_code=%s' %(post_response.status_code,get_response.status_code))

    def AtestAddEntryPoints(self):
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        new_entry_point = "/gtja"
        post_response = get_response = None
        request_URL = 'http://' + waf_config.get('HostNames')[0] + new_entry_point
        post_data = {"EntryPoints":[{"Path": new_entry_point,"CaseSensitive": 'true',"Regex": 'false',"SecureOnly": 'false'}]}
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0], self.waf_ip)
        try:
            post_response = requests.post('https://%s:8020/API/2.0/Properties/Policies' % self.waf_ip, json=post_data,auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code == 200:
                try:
                    get_response = requests.get(request_URL,verify=False)
                    if get_response.status_code == 200:
                        case_status = 'OK'
                    else:
                        case_status = 'FAIL'
                except requests.exceptions as e:
                    print(e)
                    case_status = 'FAIL'
            else:
                print('ERROR: post failed,post_status_code=%s' %post_response.status_code)
                case_status = 'FAIL'
        except requests.exceptions as e:
            print(e)
            case_status = 'FAIL'
        self.instance_actionOnClient.searchAndDeleteLine('.*' + waf_config.get('HostNames')[0])
        self.assertEqual(case_status,'OK',msg='Case failed. post_status_code=%s,get_status_code=%s' %(post_response.status_code,get_response.status_code))


    def AtestSafeLearning(self):
        self.instance_loginWaf.reInstallWAF()
        self.instance_loginWaf.changeWAFPassword()
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        self.instance_wafEasySetup.changeProtectMode('Active')
        fp_url = 'http://www.webserver1.com/rest/analytics/1.0/publish/bulk'
        post_data_enable = {"AutoLearn":{ "Enable": True}}
        post_data_url = {"urls":[fp_url]}
        enable_post_response = post_data_url = get_response = None
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0], self.waf_ip)
        try:
            enable_post_response = requests.post('https://%s:8020/API/2.0/Properties/Advanced' % self.waf_ip,
                                                 json=post_data_enable,auth=(self.ui_username, self.ui_password), verify=False)
            if enable_post_response.status_code == 200:
                post_data_url = requests.post('https://%s:8020/API/2.0/SafeLearning' % self.waf_ip,
                                              json=post_data_url,auth=(self.ui_username, self.ui_password), verify=False)
                if post_data_url.status_code == 200:
                    get_response = requests.get(fp_url,verify=False)
                    if get_response.status_code == 200:
                        case_status = 'OK'
                    else:
                        print('Cannot get this fp_url after safe learning, get_status_code=%s' % get_response.status_code)
                        case_status = 'FAIL'
                else:
                    print('post url to safe learning failed, post_status_code=%s' % post_data_url.status_code)
                    case_status = 'FAIL'
            else:
                print('post of enable safelearning  failed. post_status_code=%s' % enable_post_response.status_code)
                case_status = 'FAIL'
        except requests.exceptions as e:
            print(e)
            case_status = 'FAIL'
        self.instance_actionOnClient.searchAndDeleteLine('.*' + waf_config.get('HostNames')[0])
        self.assertEqual(case_status,'OK',msg='Case failed.enable_safelearning_post_code=%s,'
                                              'safe_learning_post_code=%s,get_fp_response_code=%s'
                                              %(enable_post_response.status_code,post_data_url.status_code,get_response.status_code) )


    def testEnableSSL(self):
        # first, ssl disable, get https://url  will be get 403(or othjer code)
        # post enable to WAF, check status code , check if success, then get https://url ,should pass, otherwise, case will fail .
        self.instance_loginWaf.reInstallWAF()
        self.instance_loginWaf.changeWAFPassword()
        waf_config = self.instance_wafEasySetup.wafEasySetup()
        request_URL = 'https://' + waf_config.get('HostNames')[0]
        post_data = {"Enabled": True}
        get_response_disable = get_response_enable = post_response = None
        self.instance_actionOnClient.addHosts(waf_config.get('HostNames')[0],self.waf_ip)
        try:
            get_response_disable = requests.get(request_URL,verify=False)
            case_status = 'FAIL'
        except requests.exceptions.ConnectionError as e:
            print(e)
            post_response = requests.post('https://%s:8020/API/2.0/Properties/SSL' % self.waf_ip,
                                          json=post_data,auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code == 200:
                get_response_enable = requests.get(request_URL,verify=False)
                if get_response_enable.status_code == 200:
                    case_status = 'OK'
                else:
                    case_status = 'FAIL'
            else:
                case_status = 'FAIL'
        self.instance_actionOnClient.searchAndDeleteLine('.*' + waf_config.get('HostNames')[0])
        if get_response_disable == None:
            self.assertEqual(case_status, 'OK',
                             msg='Case failed. get_connection_when-disabled was reset,post_enable_status_code=%s,'
                                 'get_status_code_when-enabled=%s' % (post_response.status_code,
                                 get_response_enable.status_code))
        else:
            self.assertEqual(case_status,'OK',msg='Case failed. get_status_code_when-disabled=%s,post_enable_status_code=%s,'
                                              'get_status_code_when-enabled=%s' %(get_response_disable.status_code,post_response.status_code,get_response_enable.status_code))



    '''
    @classmethod
    def tearDownClass(cls):
       cls.instance_loginWaf.removeWAF() 
    '''


if __name__=='__main__':
    suite=unittest.TestSuite()
    suite.addTest(unittest.makeSuite(wafRegression))
#    fw= open('verify_version.html','wb')
#    runner= HTMLTestRunner.HTMLTestRunner(stream=fw,title='Unittest Result',description='verify version API')
    runner=unittest.TextTestRunner(verbosity=2)
    runner.run(suite)

