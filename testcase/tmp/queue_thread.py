#!/usr/bin/python
# -*- coding=utf-8 -*-

import queue
import threading 
import requests
import time

hosts = ["http://www.htfc.com/ser*~1*/json",
        "http://www.htfc.com/serve*~1*/json",
        "http://www.htfc.com/server*~1*/json",
        "http://www.htfc.com/serv*~1*/https/json",
        "http://www.htfc.com/serverl*~1*/https/json",
        "http://www.htfc.com/main/templet/xgdl*~1.htm*",
        "http://www.htfc.com/main/templet/xgdlmm*~1.htm*"
        ]

queue = queue.Queue()

class ThreadUrl(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            host = self.queue.get()
            print(requests.get(host,verify=False))
            print(self.getName())
            print(host)
            self.queue.task_done()

start = time.time()

def main():
    
    for i in range(3):
        t = ThreadUrl(queue)
        t.setDaemon(True)
        t.start()
    for host in hosts:
        queue.put(host)
    queue.join()

main()
print("Elapsed Time: %s" % (time.time() - start))
