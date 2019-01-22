#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
bathdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(bathdir)
sys.path.insert(0, bathdir)
from common import ssh_login_WAF
import requests
import unittest
import HTMLTestRunner
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class GetWafVersion(unittest.TestCase):
    lws=ssh_login_WAF.LoginWAFSystem()
    host=lws.getHostIP()
    username,password=lws.getUsernamePassword()
        
    '''
    @classmethod
    def setUpClass(cls):  # this method will remove old WAF, intall a new version waf
        cls.lws.reInstallWAF()
        cls.lws.changeWAFPassword()
    def testGetAllVersion(self):
        current_waf_version=requests.get('https://%s:8020/API/2.0/Version' %self.host,auth=(self.username,self.password),verify=False)
        api_build_number=str(current_waf_version.json()["Major"]) + '.' + str(current_waf_version.json()["Minor"]) + '.' + str(current_waf_version.json()["Revision"]) + '.' + str(current_waf_version.json()["Build"])
        build_number=current_waf_version.json()["Build"]
        version_file_content=self.lws.connectAndExeccommand(command='cat /usr/local/waf/etc/VERSION',ret=True)
        #version_file_content=str(version_file_content,encoding='utf-8')
        print(version_file_content.split('\n'))
        for item in version_file_content.split('\n'):
            if (item.find('MAJOR') !=-1):
                waf_major=item.split('=')[1]
            if (item.find('MINOR') !=-1):
                waf_minor=item.split('=')[1]
            if (item.find('REVISION') !=-1):
                waf_revision=item.split('=')[1]
            if (item.find('BUILD') !=-1):
                waf_build_number=item.split('=')[1]
        backgroud_build_number=str(waf_major) + '.' + str(waf_minor) + '.' + str(waf_revision) + '.' + str(waf_build_number)
        self.assertEqual(api_build_number,backgroud_build_number)
    '''

    def testWafGeneral(self):
        general_value=dict(self.lws.readConfigfile('Waf_General'))
        if 'WebServerName' in general_value:
            v_WebServerName=general_value.get('WebServerName')
        else:
            print('ERROR: No WebServerName in parameter list , this testcase will be exit.')
            exit()
        if 'HostNames' in general_value:
            v_HostNames=general_value.get('HostNames').split()
        else:
            print('ERROR: No HostNames in parameter list , this testcase will be exit.')
            exit()
        v_WebServerPort=general_value.get('WebServerPort',80)
        v_ListenPort=general_value.get('ListenPort', 80)
        v_BindIP=general_value.get('BindIP',None)
        v_ListenIP=general_value.get('ListenIP',None)
        v_Bypass=general_value.get('Bypass', False)
        if(v_BindIP=='None' or v_BindIP ==''):
            v_BindIP=None
        if(v_ListenIP=='None' or v_ListenIP==''):
            v_ListenIP=None
        post_data={"ListenPort": v_ListenPort,"WebServerName": v_WebServerName,"WebServerPort": v_WebServerPort,"BindIP": v_BindIP,"HostNames": v_HostNames,"ListenIP": v_ListenIP,"Bypass": v_Bypass}    
        response_code=requests.post('https://%s:8020/API/2.0/Properties/General' %self.host,json=post_data,auth=(self.username,self.password),verify=False)
        if(response_code.find('[202]') !=-1 or response_code.find('[200]') !=-1):
        # Begin to send a request to protect web server
            add_host=ssh_login_WAF.ActionOnClient()
            for new_host_name in v_HostNames:
                add_host.addHosts(self,host,new_host_name)
        else:
            print('Set WafGeneral parameters by post is not success.')
            post_code=422

#    @classmethod
#    def tearDownClass(cls):
#       cls.lws.removeWAF() 


if __name__=='__main__':
    suite=unittest.TestSuite()
    suite.addTest(unittest.makeSuite(GetWafVersion))
#    fw= open('verify_version.html','wb')
#    runner= HTMLTestRunner.HTMLTestRunner(stream=fw,title='Unittest Result',description='verify version API')
    runner=unittest.TextTestRunner(verbosity=2)
    runner.run(suite)

