#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import time
bathdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, bathdir)
from common import ssh_login_WAF
import sqlite3
import requests
import argparse



inst_loginWAF = ssh_login_WAF.LoginWAFSystem()
inst_actionOnClinet = ssh_login_WAF.ActionOnClient()
waf_info = {'waf_ip':'10.2.8.7','ssh_user':'root','ssh_password':'Test1234','domain_name':'www.hzets.com.cn','proto':'http','safe_learning':True}

def str2bool(para):
    if para.lower() in ('yes','true','1','y'):
        return True
    elif para.lower() in ('no','false','0','n'):
        return False
    else:
        raise argparse.ArgumentTypeError('Unsupported value encountered.')

def processParameter():
    parser = argparse.ArgumentParser(description='Usage of fauto_fp:',epilog="Example: python auto_FP.py 10.2.8.7 www.baidu.com -safeL=False -user=root -password=Test1234")
    parser.add_argument('waf_IP',help='The IP address of WAF system.')
    parser.add_argument('domain_name', help='The name of protected web server.')
    parser.add_argument('-safeL',default=True, type=str2bool, help='want to safe learning or not,default value is True')
    parser.add_argument('-user', default='root', help="The user name of ssh connection,default value  is 'root'")
    parser.add_argument('-password', default='Test1234',
                        help="The password of ssh connection,default value is 'Test1234'")
    args = parser.parse_args()
    waf_info['waf_ip'] = args.waf_IP
    waf_info['domain_name'] = args.domain_name
    waf_info['ssh_user'] = args.user
    waf_info['ssh_password'] = args.password
    waf_info['safe_learning'] = args.safeL

def copyDBToLocal(waf_ip,local_path):
    username = waf_info.get('ssh_user')
    password = waf_info.get('ssh_password')
    waf_ip = waf_info.get('waf_ip')
    inst_loginWAF.stopWAFProcess(hostIP=waf_ip,user=username,password=password)
    ret_file = inst_loginWAF.connectAndExeccommand(command='ls /usr/local/waf/logs/alerts.db*',ret=True,hostIP=waf_ip,user=username,password=password)
    ret_file = ret_file.strip()
    for abs_path in ret_file.split('\n'):
        file_name = abs_path.split('/')[5]
        inst_loginWAF.sftpRemoteCopy(type='remote_read',file_name=file_name,hostIP=waf_ip,user=username,password=password,local_path=local_path,remote_path='/usr/local/waf/logs/')
    inst_loginWAF.startWAFProcess(hostIP=waf_ip,user=username,password=password)

def connectAndExecute(cmd=[],ret=False,proto='http',**kwargs):
    if kwargs.get('db_file'):
        sql_file = kwargs.get('db_file') + 'alerts.db'
    else:
        sql_file = '/usr/local/waf/logs/alerts.db'
    conn = sqlite3.connect(sql_file)
    c = conn.cursor()
    if ret:
        for sql_cmd in cmd:
            cursor = c.execute(sql_cmd)
            data = cursor.fetchall()
            return data
    else:
        with open('/home/jason/automation/auto_fp/db_result_tmp.txt','w') as fd:
            for sql_cmd in cmd:
                cursor = c.execute(sql_cmd)
                data = cursor.fetchall()
                for str_alert in data:
                    # if url has ',' , need to change the separactor in below line.
                    str_alert = ",".join('%s' % filed for filed in str_alert)
                    fd.write(str_alert)
                    fd.write('\n')
    conn.close()


# sendRequest(url_safelearning,host='',username='',password='')
def sendRequest(url_safelearning):
    waf_ip = hostIP = waf_info.get('waf_ip')
    user = waf_info.get('ssh_user')
    password = waf_info.get('ssh_password')
    cmd_list = []
    get_list = []
    request_fail = []
    for url in url_safelearning:
        cmd = 'wget  ' + url[0] + '://127.0.0.1' + url[2] + ' --header=Host:%s' % url[1] + ' --header=Referer:%s' % url[3]
        cmd_list.append(cmd)
        req_url = url[0] + '://' + url[1] + url[2]
        get_list.append(req_url)
    inst_loginWAF.newConnect(hostIP=hostIP,user=user,password=password)
    for i, cmd in enumerate(cmd_list):
        # need to make sure no duplicate element in this list
        if i == len(cmd_list)-1:
            inst_loginWAF.execCommand(command=cmd, close_ssh=True)
        else:
            inst_loginWAF.execCommand(command=cmd,close_ssh=False)
        time.sleep(3)
    #xxxxxxx
    domain = waf_info.get('domain_name')
    inst_actionOnClinet.addHosts(domain,waf_ip)
    print('Info: Total %s url will be request.' % len(get_list))
    for req_url in get_list:
        try:
            requests.get(req_url,timeout=15)
        except Exception as e:
            request_fail.append(req_url)
            print('FAIL:Send request fail.')
    return(request_fail)
    inst_actionOnClinet.searchAndDeleteLine('.*' + url_safelearning[0][1])


def saveResultToFile(alert_list,file,append='a'):
    with open(file,append) as fd:
        count = 0
        for alert in alert_list:
            fd.write('[%s]:\n' % count)
            fd.write('id:           %s \n' % alert.split(',')[0])
            fd.write('description:  %s \n' % alert.split(',')[1])
            fd.write('remote host:  %s \n' % alert.split(',')[2])
            fd.write('request:      %s \n' % alert.split(',')[3])
            fd.write('status code:  %s \n' % alert.split(',')[4])
            fd.write('reason:       %s \n' % alert.split(',')[5])
            fd.write('domain name:  %s \n' % alert.split(',')[6])
            fd.write('time:         %s \n' % alert.split(',')[7])
            fd.write('request URI:  %s \n' % alert.split(',')[8])
            fd.write('Referer:      %s \n' % alert.split(',')[9])
            fd.write('\n')
            count = count + 1


def safeLearning(local_path):
    domain_name = waf_info.get('domain_name')
    waf_ip = waf_info.get('waf_ip')
    cmd1 = ['select max(id) as sid from alerts;']
    proto = waf_info.get('proto')
    fail_url = []
    data = connectAndExecute(cmd1, ret=True, proto=proto, db_file=local_path)
    first_max_id = data[0][0]
    with open('/home/jason/automation/auto_fp/db_result_tmp.txt','r') as tmp_fd:
        url_safelearning = []
        url_FP = []
        for line in tmp_fd.readlines():
            line = line.strip('\n')
            alert = line.split(',')
            if alert[6] == domain_name:
                if alert[4] == '403':
                    url = (proto,alert[6],alert[8],alert[9])
                    url_safelearning.append(url)
                else:
                    url_FP.append(alert)
    if len(url_safelearning) >= 1:
        fail_url = sendRequest(url_safelearning)
    time.sleep(3)
    copyDBToLocal(waf_ip,local_path)
    data = connectAndExecute(cmd1,ret=True,proto=proto,db_file=local_path)
    second_max_id = data[0][0]
    url_403_end = []
    print('first count:',first_max_id)
    print('second count:',second_max_id)
    if second_max_id > first_max_id:
        cmd3 = ["select a.id,a.msg,a.ip,a.request,a.status,a.reason,a.host,a.time,a.uri,b.value from alerts as a left join request_headers as b on a.id=b.alert_id and b.name='Referer' where a.id>%d group by a.status,a.uri;" % first_max_id]
        connectAndExecute(cmd3,proto=proto,db_file=local_path)
        with open('/home/jason/automation/auto_fp/db_result_tmp.txt', 'r') as tmp_fd:
            for line in tmp_fd.readlines():
                line = line.strip('\n')
                if line.split(',')[6] == domain_name:
                    url_403_end.append(line)
    return url_FP, url_403_end, fail_url

#1. scrawler start to get url
#2. copy alerts.db to local
#3. analysis alerts in db, return aggregation alerts for 403
#4. if status code is 403, safelearning each link(send out wget request)
#5. copy alerts.db to local
#6. analysis alerts in db, return all aggregation alerts
if __name__ == '__main__':
    processParameter()
    local_path = '/home/jason/automation/auto_fp/'
    waf_ip = waf_info.get('waf_ip')
    ssh_username = waf_info.get('ssh_user')
    ssh_password = waf_info.get('ssh_password')
    proto = waf_info.get('proto')
    domain_name = waf_info.get('domain_name')
    copyDBToLocal(waf_ip,local_path)
    cmd2 = ["select a.id,a.msg,a.ip,a.request,a.status,a.reason,a.host,a.time,a.uri,b.value from alerts as a left join request_headers as b on a.id=b.alert_id and b.name='Referer' group by a.status,a.uri;"]
    connectAndExecute(cmd2, proto=proto, db_file=local_path)
    file_save = '/home/jason/automation/auto_fp/result.txt'
    if waf_info.get('safe_learning'):
        url_FP,url_403_end,fail_url = safeLearning(local_path)
        saveResultToFile(url_FP + url_403_end + fail_url, file_save, append='w')
    else:
        # no need to safe learning, read db_result_tmp.txt file and process it.
        print('INFO: no need to safe learning, read db_result_tmp.txt file and process it.')
        alert_list_end = []
        with open('/home/jason/automation/auto_fp/db_result_tmp.txt','r') as fd:
            for line in fd.readlines():
                line = line.strip('\n')
                print(line)
                print(line.split(',')[6])
                if line.split(',')[6] == domain_name:
                    print(line.split(',')[6])
                    print(domain_name)
                    alert_list_end.append(line)
        saveResultToFile(alert_list_end, file_save, append='w')
