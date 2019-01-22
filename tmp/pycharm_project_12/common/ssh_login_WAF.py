#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import paramiko
import configparser
import time
import requests
import json

class ActionOnClient(object):
    def __init__(self)
        pass
    def addHosts(self,host_name,host_ip):
        with open('/etc/hosts','a') as hosts_FD: 
            hosts_FD.write(host_ip    host_name)

    def searchAndDeleteLine(self,regular_line):
        reg_string=r'regular_line'
        with open('/etc/hosts','r',encoding='utf-8') as read_file_FD:
        with open('/etc/hosts','w',encoding='utf-8') as write_file_FD:
            for line in read_file_FD.readlines():
                if re.search(re.compile(reg_string),line):
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
    # Read configfile/waf_login_info.txt file ,got the loing info, 'section' is a tag like [WAF_SSH_Login_Info] in this file 
    def readConfigfile(self,section):
        info_list=[]
        config_file=self._HOME + '/configfile/waf_login_info.txt'
        conf=MyConfigParser()
        try:
            conf.read(config_file)
        except IOError:
            print('ERROR: File %s is not exist or cannot read.' %config_file)
            exit()
        else:
            if section in conf.sections():
                info_list=conf.items(section)
            else:
                print('ERROR: Cannot find section:%s in %s .' %(section,config_file))
        return(info_list)

    # This function will build a connection to WAF system

    def getHostIP(self):
        host_info_list=self.readConfigfile('Host_IP')
        for host_info in host_info_list:
            if 'host' in host_info:
                hostIP=host_info[1]
        if not hostIP:
            print('ERROR: Cannot read WAF IP from configuration file.')
            exit()
        return hostIP

    def getBuildNumberNeedTest(self):
        for line in self.readConfigfile('Build_Need_Run'):
            if 'build_number' in line:
                build_number_need_test=line[1]
        if not build_number_need_test:
            print('ERROR: Cannot read build number need to test from configuration file.')
            exit()
        return build_number_need_test

    def getUsernamePassword(self):
        ui_login_info_list=self.readConfigfile('WAF_UI_Login_Info')
        for ui_login_info in ui_login_info_list:
            if 'username' in ui_login_info:
                username=ui_login_info[1]
            else:
                if 'password' in ui_login_info:
                        password=ui_login_info[1]
        if not username or not password:
            print('ERROR: No username or password from configuration file.')
            exit()
        return username, password

    def newConnect(self):
        login_info_list=self.readConfigfile('WAF_SSH_Login_Info')
        for login_info in login_info_list:
            if 'username' in login_info:
                username=login_info[1]
            else:
                if 'password' in login_info:
                    password=login_info[1]
        host_info_list=self.readConfigfile('Host_IP')
        for host_info in host_info_list:
            if 'host' in host_info:
                host=host_info[1]
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
    def execCommand(self,command='ls -l',ret=False):
        ssh_FD=open(self._HOME + '/log/ssh.log', 'wb')
        if isinstance(command,list):
            for cmd in command:
                stdin,stdout,stderr=self._new_ssh.exec_command(cmd)
                result=stdout.read()
                if not result:
                    result=stderr.read()
                if ret:
                    return (str(result,encoding='utf-8'))
                else:
                    ssh_FD.write(result)
                time.sleep(1)
        else:
            stdin,stdout,stderr=self._new_ssh.exec_command(command)
            result=stdout.read()
            if not result:
                result=stderr.read()
            if ret:
                return (str(result,encoding='utf-8'))
            else:
                ssh_FD.write(result)
        ssh_FD.close()
        self._new_ssh.close()
    def connectAndExeccommand(self,command='ls -l',ret=False):
        self.newConnect()
        if ret:
            return_value=self.execCommand(command,ret)
            return return_value
        else:
            self.execCommand(command,ret)
    #this method can has one argument(build number,such as: 8.0.2.4786), or no arguments, if no argument was given , this method will read config file 
    #this method will do: 1. check was installed or not 2. WAF  installed, then remove it 3. install new waf 4.add port on firewall 5. check new installed waf is running or not
    def reInstallWAF(self,*args):
        if len(args):
            build_number_need_test=args[0]
        else:
            build_number_need_test= self.getBuildNumberNeedTest()
        build_need_test='/root/' + 'zyWAF-' + build_number_need_test + '.centos7.x86_64.rpm'
        file_exist_return=self.connectAndExeccommand(command='ls %s' %build_need_test,ret=True)
        if(file_exist_return.find('No such file or directory') !=-1):
            print('ERROR: Cannot find build file %s in /root/ directory on WAF system under test.' %build_need_test)
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
            'firewall-cmd --reload',
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
            print(item)
            if (item.find('wafmanager') !=-1):
                wafmanager=True
            if (item.find('/usr/local/waf/bin/waf') !=-1):
                wafcore=True
        if not (wafmanager and wafcore):
            print('ERROR: Look like WAF is not run normally.Scripts will exit.')
            exit()

    # This method will change the WAF UI login  password, **kwargs can be: old_password='admin', new_password='Test1234'
    def changeWAFPassword(self,**kwargs):
        if(len(kwargs)):
            if 'old_password' in kwargs:
                old_password=kwargs.get('old_password')
            else:
                old_password='admin'
            if 'new_password' in kwargs:
                new_password=kwargs.get['new_password']
            else:
                uname,new_password=self.getUsernamePassword()
        else:
            old_password='admin'
            new_password='Test1234'
        post_data={'OldPassword': old_password,'Password': new_password}       
        host=self.getHostIP()
        print('current_passwd: %s, new password: %s' %(old_password,new_password))
        password_change_return=requests.patch('https://%s:8020/API/2.0/CurrentUser' %host,json=post_data,auth=('admin',old_password),verify=False)
        print(password_change_return)

    # This method will stop waf process, remove waf rpm packages, delete the install directory
    def removeWAF(self):
        return_waf_build=self.connectAndExeccommand(command='rpm -qa|grep WAF',ret=True)
        if return_waf_build.startswith('zyWAF'):
            waf_build=return_waf_build[0:11]
        self.stopWAFProcess()
        cmd_list=[
        'rpm -e %s' %waf_build,
        'rm -rf /usr/local/waf/']
        self.connectAndExeccommand(command=cmd_list,ret=False)
 
    def stopWAFProcess(self):
        #self.connectAndExeccommand(command='systemctl stop zywaf',ret=False)
        ps_return=self.connectAndExeccommand(command='ps -ax|grep waf',ret=True)
        for line in ps_return.split('\n'):
            if (line.find('/usr/local/waf/bin/wafmanager') !=-1):
                wafmanager_pid=line.split()[0]
                self.connectAndExeccommand(command='kill -9 %s' %wafmanager_pid,ret=False)
            if (line.find('/usr/local/waf/bin/waf --no-daemon') !=-1):
                wafcore_pid=line.split()[0]
                self.connectAndExeccommand(command='kill -9 %s' %wafcore_pid,ret=False)
        print('wafmanager process ID: %s, wafcore process ID:%s' %(wafmanager_pid,wafcore_pid))
# need do: check requests return , auth fail should show error.
# check the data type of exeCommand 
