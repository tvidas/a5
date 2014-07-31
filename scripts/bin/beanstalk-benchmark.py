# -*- coding: utf-8 -*-

#  time python beanstalk-benchmark.py write
#  time python beanstalk-benchmark.py read

import beanstalkc
import sys, time, datetime

#Read and execute global config
sys.path.append('../config')
from config import *

 
def main():
    # time python test.py
    if len(sys.argv) < 2:
        print("need write or read parameter")
        return
    c = beanstalkc.Connection(host=BSHOST, port=BSPORT)
    
    i, action = 0, sys.argv[1]
    print( str(datetime.datetime.now())+" start "+action+"  ... ")
    t1 = time.time()
    if action == 'write':
        i = queue_write(c, 1000000)
    else:
        i = queue_read(c)
    t2= time.time()
    duration = (t2-t1)*1000.0
    text = str(datetime.datetime.now())+" "+action+" "+str(i)+" entries in "+('% 4.f ms' % duration)
    print(text)
 
def queue_write(c, max):
    for i in range(1,max+1):
        c.put('queue entry!'+str(i))
    return i
 
def queue_read(c):
    i,job=0,True
    t1 = time.time()
    while job:
        job = c.reserve(timeout=0)
        #print (job.body)
        #print(job.delete())
        if job:
            job.delete()
            i+=1
    return i
 
if __name__ == '__main__':
    main()
 
