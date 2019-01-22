#!/usr/bin/python 
# -*- coding=utf-8 -*-

import argparse

def str2bool(para):
    if para.lower() in ('yes','true','1','y'):
        return True
    elif para.lower() in ('no','false','0','n'):
        return False
    else:
        raise argparse.ArgumentTypeError('Unsupported value encountered.')

parser = argparse.ArgumentParser(description='Usage of fauto_fp:',epilog="Example: python argparser_test.py 10.2.8.7 www.baidu.com -safeL=False -user=root -password=Test1234")
parser.add_argument('waf_IP',metavar='ip',help='The IP address of WAF system.')
parser.add_argument('domain_name',help='The name of protected web server.')
parser.add_argument('-safeL',type=str2bool,default=True,help='need to safe learning or not')
parser.add_argument('-user',default='root',help="The user name of ssh connection,usually it is 'root'")
parser.add_argument('-password',default='Test1234',help="The password of ssh connection,default value is 'Test1234'")

args = parser.parse_args()
print(args)
print('waf ip:',args.waf_IP)
print('domian name:',args.domain_name)
print('user name:',args.user)
if args.safeL:
    print('need safe learning')
else:
    print('safeL is False')



