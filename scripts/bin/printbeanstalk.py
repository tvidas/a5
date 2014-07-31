#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       printbeanstalk.py


import beanstalkc
from pprint import pprint

#Read and execute global config
sys.path.append('../config')
from config import *


beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)

pprint(beanstalk.stats())

print "tubes: "
print beanstalk.tubes()

pprint(beanstalk.stats_tube(BSMSBOXQ))


#for testing reserve and "putback" (non-delete)
#beanstalk.watch(BSMSBOXQ)
#job = beanstalk.reserve()

beanstalk.use(BSMSBOXQ)
job = beanstalk.peek_ready()

if job is None:
	print "peek ready failed"
else:
	pprint(job.stats())
	print job.body


