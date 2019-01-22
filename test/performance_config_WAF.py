#!/usr/bin/python 
# -*- coding: utf-8 -*-

import sys
import ftplib
import os
import time
import socket
import requests
import json

class SetupWAF():
    def __init__(self):
        pass

    def downloadBuild(self,build_release,small_version,big_version="8.0.2"):
        ftp_path="build/waf/" + build_release + small_version
        build_name="zyWAF-" + big_version + "-" + small_version + ".centos7.x86_64.rpm"
        bufsize=1024
        localpath="/home/build/" + build_release + small_version +"/"
        IP=''
        Port=''
        ftp_user=''
        ftp_passwd=''
        ftp_file=open('ftp_server.txt')
        lines=ftp_file.readlines()
        for line in lines:
            if line.find("host") != -1:
                IP=line.split(":")[1]
            elif line.find("port") != -1:
                Port=line.split(":")[1]
            elif line.find("user") != -1:
                ftp_user=line.split(":")[1]
            elif line.find("password") != -1:
                ftp_passwd=line.split(":")[1]
        ftp_file.close()
        ftp=ftplib.FTP()
        try:
            ftp.connect(host=IP,port=Port)
        except(socket.error,socket.gaierror) as e:
            print("ERROR: Cannot access '%s' FTP server!! %s")  %(IP,e)
            sys.exit(0)
        try:
            ftp.login(user=ftp_user,passwd=ftp_passwd)
        except ftplib.error_perm as e:
            print("ERROR: Login error, please check the username and password,error code: %s")  %e
            exit()
        try:
            ftp.cwd(ftp_path)
        except ftplib.error_perm as e:
            print("ERROR: Cannot access this directory: %s") %e
        if build_name in ftp.nlst():
            build_size=ftp.size(build_name)
            file_local=open(localpath+build_name,"wb").write
            try:
                ftp.retrbinary("RETR %s" %build_name,file_local,bufsize)
            except ftplib.error_perm as e:
                print("ERROR: Cannot read ftp server_file, you may not have permission to access this file: %s") %e
            download_file_size=os.system("wc -c %s | awk '{print $1}'") %(localpath+build_name)
            if download_file_size != build_size:
                print("Error: You did not download a complete package.")
                sys.exit(0)

    def copyAndUpgrade(self,waf_ip,build_release,small_version, big_version="8.0.2"):
        print("The default build directory on current server: /home/build")
        build_name="zyWAF-" + big_version + "-" + small_version + ".centos7.x86_64.rpm"
        build_path="/home/build/" + build_name
        # build should be download to /home/build/ directory
        if  not os.path.exists(build_path ):
            # downloadBuild function will not be used now , because this scripts will run in lab environment.
            # downloadBuild(build_release,small_version, big_version="8.0.2")
            print("ERROR: Please copy the build to /home/build/ on current server!!!")
            sys.exit(0)
        """
        os.system("scp %s root@%s:/home/" %(build_path,waf_ip)) 
        print("build_path1111111111111:%s" %build_path)
        time.sleep(10)
        # ssh to WAF , upgrade WAF, call WAF API, check upgrade status
        try:
            waf_build_path="/home/" + build_name
            os.system("/usr/bin/sshpass -p Test1234 ssh root@%s /usr/local/waf/bin/zywaf_upgrade.sh upgrade %s" %(waf_ip,waf_build_path)) 
        except Exception as e:
            print("ERROR: Cannot upgrade WAF: %s ") %e
        time.sleep(10)
        """
        # check WAF version, default username is admin, password is Test1234
        api_build_version_return=requests.get('https://%s:8020/API/2.0/Version' %waf_ip, auth=('admin','Test1234'),verify=False) 
        # api_build_version_return=os.system("curl -k -u admin:Test1234 https://%s:8020/API/2.0/Version") %(waf_ip)
        print("Version response;%s" %api_build_version_return)
        main_version=api_build_version_return.json()["Major"] + api_build_version_return.json()["Minor"] + api_build_version_return.json()["Revision"]
        build_number=api_build_version_return.json()["Build"] 
        if(main_version == big_version and small_version == build_number):
            print("Info: Upgrade successfully. ")
        else:
            print("ERROR: Upgrade failed. You need to upgrade by manual.")

    # configure WAF, operation=set_website : will setup website name, ip, port. operation=set_ssl : will enable ssl connecton to server
    def configWAF(self,waf_ip,operation,**kwargs):
        if operation=="set_websites":
            # configWAF(waf_ip,set_websites,site="xx",ip="xx",port="xx",mode="active/passivve")
            site_name=kwargs["site"]
            site_ip=kwargs["ip"]
            site_port=kwargs["port"]
            if 'mode' in kwargs.keys():
                mode=kwargs["mode"]
            else:
                mode="passive"
            post_data={"ListenPort": 80,"WebServerName": site_ip,"WebServerPort": site_port,"BindIP": None,"HostNames": [site_name],"ListenIP": None,"Bypass": False}
            #post_data=json.dumps(post_data)
            #post_headers={"Content-Type": "application/json"}
            response_config=requests.post('https://%s:8020/API/2.0/Properties/General' %waf_ip,json=post_data,auth=('admin','Test1234'),verify=False)
            print(response_config)
            time.sleep(3)
            api_general_return =requests.get('https://%s:8020/API/2.0/Properties/General' %waf_ip, auth=('admin', 'Test1234'),verify=False)
            print("ip address:%s , hostname:%s , server port:%s" %(site_ip, site_name, site_port))
            print("get response:%s" %api_general_return.json())
            print(api_general_return.json()["WebServerName"])
            print(api_general_return.json()["HostNames"][0])
            print(api_general_return.json()["WebServerPort"])
            if(api_general_return.json()["WebServerName"]!=site_ip or api_general_return.json()["HostNames"][0]!=site_name or api_general_return.json()["WebServerPort"]!=site_port):
                print("ERROR: Parameters of be protected web site cannot be setup, scritps will be exit!")
                sys.exit(0)
        elif(operation=="set_ssl"):
            # configWAF(waf_ip,set_ssl,ssl_eanble="ture/false")
            ssl_enable=kwargs["ssl_enable"]
            post_data={'"ListenPort": 443,'
                       '"CAFile": null,'
                       '"EnctyptToServer": true,'
                       '"ServerPort": 443,'
                       '"Enabled": %s,'
                       '"CertificateFile": "/usr/local/waf/cert/watest.crt"'
                       '"ListenIP": null,'
                       '"CertificateKeyFile": "/usr/local/waf/cert/watest.key"'}
            #post_data=json.dump(post_data)
            #post_headers={"Content-Type": "application/json"}
            requests.post('https://%s:8020/API/2.0/Properties/General' %waf_ip,json=post_data,auth=('admin','Test1234'),verify=False)
            time.sleep(3)
            api_ssl_return =requests.get('https://%s:8020/API/2.0/Properties/General' %waf_ip, auth=('admin', 'Test1234'),verify=False)
            if(api_ssl_return.json()["ListenPort"]!=443 or api_ssl_return.json()["CAFile"]!="null" or api_ssl_return.json()["EnctyptToServer"]!="true" or api_ssl_return.json()["ServerPort"]!=443 \
                or api_ssl_return.json()["Enabled"]!="true" or api_ssl_return.json()["CertificateFile"]!="/usr/local/waf/cert/watest.crt" or api_ssl_return.json()["ListenIP"]!="null" \
                or api_ssl_return.json()["CertificateKeyFile"]!="/usr/local/waf/cert/watest.key"):
                print("ERROR:Parameters of SSL info cannot be setup,scripts will be exit!")
                sys.exit(0)
    #run bash scripts, this scripts will create a result file: perf_result.txt
    def runPerformanceTest(self,script_path):
        os.system("bash %s") %(script_path)
        time.sleep(300)
        result_file=os.path.dirname(script_path) + '/perf_result.txt'
        if not os.path.exists(result_file):
            print("ERROR: ab test result does not exist,scripts will exit! ")
            sys.exit(0)
        fh_ab_result=open(result_file)
        lines=fh_ab_result.readlines()
        for line in lines:
            if not line.split(','):
                print("ERROR: One line result is empty , you need to re-run this performance test!")
                sys.exit(0)

          
if __name__=='__main__':
    new_waf=SetupWAF()
    #copyAndUpgrade(self,waf_ip,build_release,small_version, big_version="8.0.2")
    waf_ip='10.2.178.134'
    build_release='dev'
    small_version='4577'
    big_version='8.0.2'
    build_name="zyWAF-" + big_version + "-" + small_version + ".centos7.x86_64.rpm"
    print("Build version: %s") %build_name
    new_waf.copyAndUpgrade(waf_ip,build_release,small_version,big_version="8.0.2")
    print("upgrade configuration:")
    # configWAF(waf_ip,set_websites/set_ssl,site="xx",ip="xx",port="xx",mode="active/passivve")
    new_waf.configWAF(waf_ip,'set_websites',site='www.performance.com',ip='10.2.178.111',port='8019')
    





