#!/usr/bin/python 
# -*- coding=utf-8 -*-

import threading 
import time

def newPrint(n):
    print('1: HaHa HaHa:%s' % n)
    time.sleep(2)
    print('2: HeHe')
    time.sleep(1)
    print('Wait:')

for i in range(3):
    print(i)
    t = threading.Thread(target=newPrint,args=('t-%s' % i,))
    print('a')
    t.setDaemon(True)
    print('b')
    t.start()
    print('c')

    
t.join()
time.sleep(8)
print(threading.active_count())

