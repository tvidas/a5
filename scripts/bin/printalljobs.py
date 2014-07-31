#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       printalljobs.py


import beanstalkc
from pprint import pprint

#Read and execute global config
sys.path.append('../config')
from config import *


beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)

pprint(beanstalk.stats())

print "tubes: "
print beanstalk.tubes()



if BSMSBOXQ in beanstalk.tubes():
	pprint(beanstalk.stats_tube(BSMSBOXQ))

	beanstalk.use(BSMSBOXQ)
	#next ready one

	for i in range(5000):
		job = beanstalk.peek(i)

		if job is None:
			#print "peek ready " + str(i) + " failed"
			y = 0
		else:
			print str(i) + "=" +job.body
			#pprint(job.stats())

	print "next job: "

	job = beanstalk.peek_ready()
	if job is None:
		print "peek ready failed"
	else:
		print job.body
		pprint(job.stats())

	print str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-ready']) + " samples ready to process"
	print str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-reserved']) + " samples are processing"
	print str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-delayed']) + " samples are delayed"

	if job is not None:
		beanstalk.watch(BSMSBOXQ)
		job = beanstalk.reserve()
		job.release(delay=10)
else:
	print 'malware tube is empty'
