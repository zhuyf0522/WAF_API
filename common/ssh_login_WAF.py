#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import paramiko
import configparser
import time
import requests
import socket
import re
import subprocess
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from scapy.all import *
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Read configfile/waf_login_info.txt file ,got the loing info, 'section' is a tag like [WAF_SSH_Login_Info] in this file
def readConfigfile(section,*args):
    if len(args) == 1:
        item = args[0]
    config_file = os.path.abspath('..') + '/configfile/waf_login_info.txt'
    conf = MyConfigParser()
    try:
        conf.read(config_file)
    except IOError:
        print('ERROR: File %s is not exist or cannot read.' % config_file)
        exit()
    else:
        if section == 'WAF_IP':
            return conf.get(section,'host')
        elif section == 'WAF_SSH_Login_Info':
            return conf.get(section,'username'),conf.get(section,'password')
        elif section == 'WAF_UI_Login_Info':
            return conf.get(section,'username'), conf.get(section,'password')
        elif section == 'Build_Need_Run':
            return conf.get(section,'build_number')
        elif section == 'WAF_General':
            v_WebServerPort = conf.get(section,'WebServerPort')
            v_ListenPort = conf.get(section,'ListenPort')
            v_BindIP = conf.get(section, 'BindIP')
            v_WebServerName = conf.get(section,'WebServerName')
            v_ListenIP = conf.get(section,'ListenIP')
            v_HostNames = conf.get(section,'HostNames')
            v_Bypass = conf.get(section,'Bypass')
            return {'WebServerPort': v_WebServerPort,'ListenPort': v_ListenPort,'BindIP':v_BindIP,'WebServerName':v_WebServerName,'ListenIP':v_ListenIP,'HostNames':v_HostNames,'Bypass':v_Bypass}
        else:
            return conf.get(section,item)

def getHostIP():
    """
    search IP, now only support local machine ipaddress
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('103.235.46.39', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def getHttpHeader(pcap_file,search_item):
    packet_list = rdpcap(pcap_file)
    for packet in packet_list:
        if 'Raw' in packet:
            http_header = bytes.decode(packet['Raw'].load).split('\r\n')
            for item in http_header:
                if item.find(search_item) != -1:
                    item_value = item.split(':')[1]
                    return item_value.strip()


class ConfigWafByAPI(object):
    def __init__(self,waf_IP,username,password,waf_basic_setting):
        self.waf_IP = waf_IP
        self.ui_username = username
        self.ui_password = password
        self.general_value = waf_basic_setting
        self.inst_loginWafSystem = LoginWAFSystem()

    def wafEasySetup(self):
        v_WebServerName = self.general_value.get('WebServerName')
        v_HostNames = self.general_value.get('HostNames').split(',')
        v_WebServerPort = self.general_value.get('WebServerPort', 80)
        v_ListenPort = self.general_value.get('ListenPort', 80)
        v_BindIP = self.general_value.get('BindIP', None)
        v_ListenIP = self.general_value.get('ListenIP', None)
        v_Bypass = self.general_value.get('Bypass', False)
        if v_BindIP == 'None' or v_BindIP == '':
            v_BindIP = None
        if v_ListenIP == 'None' or v_ListenIP == '':
            v_ListenIP = None
        post_data = {"ListenPort": v_ListenPort, "WebServerName": v_WebServerName, "WebServerPort": v_WebServerPort,
                 "BindIP": v_BindIP, "HostNames": v_HostNames, "ListenIP": v_ListenIP, "Bypass": v_Bypass}
        try:
            post_response = requests.post('https://%s:8020/API/2.0/Properties/General' % self.waf_IP, json=post_data,
                                  auth=(self.ui_username, self.ui_password), verify=False)
            if post_response.status_code in [202,200]:
                self.inst_loginWafSystem.stopAndStartWafProcess()
                return post_data
            else:
                print('ERROR: easy setup post response code is: %s,  not 200 or 202, post failed.' %post_response.status_code)
                exit()
        except requests.exceptions as e:
            print(e)
            exit()

    # this method can change WAF protection mode. mode= Passive/Active
    def changeProtectMode(self,mode):
        if mode == 'Passive':
            post_data = {"PassiveMode": True}
        elif mode == 'Active':
            post_data = {"PassiveMode": False}
        else:
            print('ERROR: Cannot recognize protection mode, parameters transfer to this method is wrong.')
            exit()
        try:
            mode_response = requests.post('https://%s:8020/API/2.0/Properties/Advanced' % self.waf_IP, json=post_data,
                                  auth=(self.ui_username, self.ui_password), verify=False)
        except requests.exceptions.ConnectionError as e:
            print(e)
        time.sleep(5)
        if mode_response.status_code in [200 , 202 , 304]:
            self.inst_loginWafSystem.stopAndStartWafProcess()
            time.sleep(5)
        else:
            print('Change mode failed. post_status_code=%s' % mode_response.status_code)
            exit()
        try:
            get_response = requests.get('https://%s:8020/API/2.0/Properties/Advanced' % self.waf_IP, json=post_data,
                                  auth=(self.ui_username, self.ui_password), verify=False)
            if get_response.status_code == 200:
                if get_response.json()["PassiveMode"] != post_data.get("PassiveMode"):
                    print('ERROR: protection mode is not set value.')
                    exit()
            else:
                print('ERROR: Response for /Properties/Advanced is not 200, get_response_code=%s' % get_response.status_code)
                exit()
        except requests.exceptions as e:
            print('ERROR: No get response for /Properties/Advanced.')
            exit()


class ActionOnClient(object):
    def __init__(self):
        pass

    def addHosts(self,host_name,host_ip):
        with open('/etc/hosts','a') as hosts_FD: 
            hosts_FD.write(host_ip + '    ' + host_name + '\n')

    def searchAndDeleteLine(self,regular_line):
        with open('/etc/hosts','r',encoding='utf-8') as read_file_FD:
            lines=read_file_FD.readlines()
            with open('/etc/hosts','w',encoding='utf-8') as write_file_FD:
                for line in lines:
                    #print(re.compile(reg_string))
                    if re.search(re.compile(r'%s' % regular_line),line):
                        continue
                    write_file_FD.write(line)


class MyConfigParser(configparser.ConfigParser):
    def __init__(self,defaults=None):
        configparser.ConfigParser.__init__(self,defaults=defaults)

    def optionxform(self, optionstr):
        return optionstr


class LoginWAFSystem():
    _HOME=os.path.abspath('..')
    _new_ssh=''

    def __init__(self):
        pass

    # **kwargs = {hostIP='',user='',password=''}
    def newConnect(self,**kwargs):
        if len(kwargs) >= 3:
            host = kwargs.get('hostIP')
            username = kwargs.get('user')
            password = kwargs.get('password')
        else:
            username,password = readConfigfile('WAF_SSH_Login_Info')
            host = readConfigfile('WAF_IP')
        if not username or not password or not host:
            print('ERROR: Host or Username or Password is empty.')
            exit()
        try:
            self._new_ssh=paramiko.SSHClient()
            self._new_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  #auto access host which  not in known_host file  
            self._new_ssh.connect(host,22,username,password)
        except Exception as e:
            print(e)
            exit()
    # This function will execute command on WAF system , if command can be a single command string, or a list(command list), ret=True will return command return value
    # The return data type is 'str'
    # add run command on local machine

    def execCommand(self,command='ls -l',ret=False,local=False,close_ssh=True):
        ssh_FD=open(self._HOME + '/log/ssh.log', 'wb')
        if isinstance(command,list):
            for cmd in command:
                if local:
                    output=subprocess.getoutput(cmd)
                    time.sleep(3)
                    if ret:
                        return output
                    else:
                        ssh_FD.write(output)
                else:
                    stdin,stdout,stderr=self._new_ssh.exec_command(cmd)
                    result=stdout.read()
                    if not result:
                        result=stderr.read()
                    if ret:
                        return str(result,encoding='utf-8')
                    else:
                        ssh_FD.write(result)
                time.sleep(1)
        else:
            if local:
                output = subprocess.getoutput(command)
                time.sleep(3)
                if ret:
                    return output
                else:
                    ssh_FD.write(output)
            else:
                stdin,stdout,stderr=self._new_ssh.exec_command(command)
                result=stdout.read()
                if not result:
                    result=stderr.read()
                if ret:
                    return str(result,encoding='utf-8')
                else:
                    ssh_FD.write(result)
        if close_ssh:
            ssh_FD.close()
            self._new_ssh.close()


    # sftpRemoteCopy(type='',file_name='',hostIP='',user='',password='',local_path='',remote_path='')
    # such as : local_path = /home/jason/automation,  no file name in path
    def sftpRemoteCopy(self,**kwargs):
        type = kwargs.get('type')
        file_name = kwargs.get('file_name')
        host = kwargs.get('hostIP')
        port = 22
        username = kwargs.get('user')
        password = kwargs.get('password')
        if kwargs.get('local_path') and kwargs.get('remote_path'):
            local_path = kwargs.get('local_path')
            remote_path = kwargs.get('remote_path')
        else:
            local_path = readConfigfile('Pcap_Path','local_path')
            remote_path = readConfigfile('Pcap_Path','remote_path')
        try:
            t = paramiko.Transport(host,port)
            t.connect(username=username,password=password)
            sftp = paramiko.SFTPClient.from_transport(t)
            if type == 'remote_read':
                sftp.get(remote_path + file_name,local_path + file_name)
            elif type == 'remote_write':
                sftp.put(local_path + file_name,remote_path + file_name)
            else:
                print('ERROR: type is error:%s, it should be remote_read or remote_write.' % type)
        except Exception as e:
            print(e)
    # **kwargs = {command='ls -l',ret=False,hostIP='',user='',password='',local=False,close_ssh=True}
    def connectAndExeccommand(self,command='ls -l',ret=False,**kwargs):
        #print(kwargs)
        self.newConnect(**kwargs)
        if ret:
            return_value=self.execCommand(command,ret)
            return return_value
        else:
            self.execCommand(command,ret)

    def getHostInterface(self,local=False,**kwargs):
        if local:
            output = subprocess.getoutput('ifconfig')
        else:
            output = self.connectAndExeccommand('ifconfig',ret=True,**kwargs)
        total_interface_fileds = output.split('0\n\n')
        ipaddress = kwargs.get('hostIP')
        for filed in total_interface_fileds:
            if filed.find(ipaddress):
                interface_name = filed.split(':')[0]
                return interface_name
        print('ERROR: Cannot find the interface for ip address:%s' % ipaddress)


    #this method can has one argument(build number,such as: 8.0.2.4786), or no arguments, if no argument was given , this method will read config file 
    #this method will do: 1. check waf was installed or not 2. WAF  installed, then remove it 3. install new waf 4.add port on firewall 5. check new installed waf is running or not
    def reInstallWAF(self,*args):
        if len(args):
            build_number_need_test=args[0]
        else:
            build_number_need_test= readConfigfile('Build_Need_Run')
        build_need_test='/root/' + 'zyWAF-' + build_number_need_test + '.centos7.x86_64.rpm'
        file_exist_return=self.connectAndExeccommand(command='ls %s' %build_need_test,ret=True)
        if file_exist_return.find('No such file or directory') !=-1:
            print('ERROR: Cannot find build file %s in /root/ directory on WAF system under test.' % build_need_test)
            exit()
        return_waf_build=self.connectAndExeccommand(command='rpm -qa|grep WAF',ret=True)
        if return_waf_build.startswith('zyWAF'):
            waf_build=return_waf_build[0:11]
            self.stopWAFProcess()
            cmd_list=[
            'rpm -e %s' %waf_build,
            'rm -rf /usr/local/waf/',
            'rpm -ivh %s' %build_need_test,
            'service zywaf start',
            'firewall-cmd --permanent --add-port=80/tcp',
            'firewall-cmd --permanent --add-port=8080/tcp',
            'firewall-cmd --permanent --add-port=443/tcp',
            'firewall-cmd --reload'
            ]
        else:
            cmd_list=['rpm -ivh %s' %build_need_test,
            'service zywaf start',
            'firewall-cmd --permanent --add-port=80/tcp',
            'firewall-cmd --permanent --add-port=8080/tcp',
            'firewall-cmd --permanent --add-port=443/tcp',
            'firewall-cmd --reload',
            ]
        self.connectAndExeccommand(command=cmd_list,ret=False)
        ps_content=self.connectAndExeccommand(command='ps -ax|grep waf',ret=True)
        wafmanager=False
        wafcore=False
        for item in ps_content.split('\n'):
            if item.find('wafmanager') !=-1:
                wafmanager=True
            if item.find('/usr/local/waf/bin/waf') !=-1:
                wafcore=True
        if not (wafmanager and wafcore):
            print('ERROR: Look like WAF is not run normally.Scripts will exit.')
            exit()

    # This method will change the WAF UI login  password, **kwargs can be: old_password='admin', new_password='Test1234'
    def changeWAFPassword(self,**kwargs):
        if len(kwargs):
            if 'old_password' in kwargs:
                old_password=kwargs.get('old_password')
            else:
                old_password='admin'
            if 'new_password' in kwargs:
                new_password=kwargs.get('new_password')
            else:
                uname,new_password=readConfigfile('WAF_UI_Login_Info')
        else:
            old_password='admin'
            new_password='Test1234'
        post_data={'OldPassword': old_password,'Password': new_password}       
        host=readConfigfile('WAF_IP')
        print('current_passwd: %s, new password: %s' %(old_password,new_password))
        try:
            password_change_return=requests.patch('https://%s:8020/API/2.0/CurrentUser' %host,json=post_data,
                                                  auth=('admin',old_password),verify=False)
            if password_change_return.status_code != 200:
                print('Error: Look like password change failed, patch_status_code=%s' %password_change_return.status_code)
                exit()
        except requests.exceptions as e:
            print(e)
            exit()


    # This method will stop waf process, remove waf rpm packages, delete the install directory

    def removeWAF(self):
        return_waf_build=self.connectAndExeccommand(command='rpm -qa|grep WAF',ret=True)
        waf_build=''
        if return_waf_build.startswith('zyWAF'):
            waf_build=return_waf_build[0:11]
        else:
            print('ERROR: Cannot got build number from rpm -qa|grep waf.')
            exit()
        self.stopWAFProcess()
        cmd_list=[
        'rpm -e %s' %waf_build,
        'rm -rf /usr/local/waf/']
        self.connectAndExeccommand(command=cmd_list,ret=False)

    def stopWAFProcess(self,**kwargs):
        self.connectAndExeccommand(command='systemctl stop zywaf',ret=False,**kwargs)
        ps_return=self.connectAndExeccommand(command='ps -ax|grep waf',ret=True,**kwargs)
        for line in ps_return.split('\n'):
            if line.find('/usr/local/waf/bin/wafmanager') !=-1:
                wafmanager_pid=line.split()[0]
                self.connectAndExeccommand(command='kill -9 %s' %wafmanager_pid,ret=False,**kwargs)
            if line.find('/usr/local/waf/bin/waf --no-daemon') !=-1:
                wafcore_pid=line.split()[0]
                self.connectAndExeccommand(command='kill -9 %s' %wafcore_pid,ret=False,**kwargs)

    def startWAFProcess(self,**kwargs):
        self.connectAndExeccommand(command='systemctl start zywaf',**kwargs)

    def stopAndStartWafProcess(self):
        self.stopWAFProcess()
        time.sleep(3)
        self.connectAndExeccommand(command='systemctl start zywaf',ret=False)
        time.sleep(2)
        ps_return = self.connectAndExeccommand(command='systemctl status zywaf', ret=True)
        waf_process_status = wafmanager_pid = wafcore_pid = False
        for line in ps_return.split('\n'):
            if (line.find('active (running)') != -1 ) :
                waf_process_status = True
                continue
            if (line.find('/usr/local/waf/bin/wafmanager') !=-1):
                wafmanager_pid = True
                continue
            if (line.find('/usr/local/waf/bin/waf --no-daemon') !=-1):
                wafcore_pid = True
        if not (waf_process_status and wafmanager_pid and wafcore_pid):
            print('ERROR: Look like zywaf is not start successfully.Scripts will be exit.')
            exit()

# need do: check requests return , auth fail should show error.
# check the data type of exeCommand 
