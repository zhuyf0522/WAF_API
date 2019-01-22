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
from nose_parameterized import parameterized
#import HTMLTestRunner
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Advanced(unittest.TestCase):
    instance_loginWaf=ssh_login_WAF.LoginWAFSystem()
    waf_ip = ssh_login_WAF.readConfigfile('WAF_IP')
    ssh_username, ssh_password = ssh_login_WAF.readConfigfile('WAF_SSH_Login_Info')
    ui_username, ui_password = ssh_login_WAF.readConfigfile('WAF_UI_Login_Info')
    waf_general_conf = ssh_login_WAF.readConfigfile('WAF_General')
    instance_wafEasySetup = ssh_login_WAF.ConfigWafByAPI(waf_ip, ui_username, ui_password, waf_general_conf)
    instance_actionOnClient = ssh_login_WAF.ActionOnClient()

    '''   
    @classmethod
    def setUpClass(cls):  # this method will remove old WAF, intall a new version waf
        cls.instance_loginWaf.reInstallWAF()
        cls.instance_loginWaf.changeWAFPassword()
        cls.instance_wafEasySetup.wafEasySetup()
    '''
    @unittest.skipIf(waf_general_conf.get('WebServerName') != '10.2.178.131', reason='waf ip should be 10.2.178.131,case use jira on this os')
    @parameterized.expand(['GET', 'POST','HEAD','PUT','OPTIONS','PATCH','DELETE'])
    def testHttpMethod(self, method):
        post_data = {"HTTPMethods": [method]}
        request_url = 'http://www.webserver1.com'
        waf_url = 'https://%s:8020/API/2.0/Properties/Advanced' % self.waf_ip
        case_status = ''
        try:
            post_response = requests.post(waf_url,json=post_data,auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code not in [200,202,304]:
                case_status = 'FAIL'
                self.assertEqual(case_status, 'OK',
                                 msg='Post_response_code:%s, post failed' % post_response.status_code)
                return
        except requests.exceptions as e:
            print(e)
        try:
            request_response = requests.request(method=method,url=request_url)
            if request_response.status_code == 200:
                case_status = 'OK'
            else:
                case_status = 'FAIL'
        except requests.exceptions as e:
            print(e)
        self.assertEqual(case_status,'OK',msg='Case failed, post_status_code=%s, request_status_code=%s' %(post_response.status_code,request_response.status_code))







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

