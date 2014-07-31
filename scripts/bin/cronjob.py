#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       cronjob.py


import beanstalkc

#Read and execute global config
sys.path.append('../config')
from config import *


beanstalk = beanstalkc.Connection(host=BSHOST)

if BSMSBOXQ in beanstalk.tubes():
	beanstalk.use(BSMSBOXQ)

	print str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-ready']) + "," + str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-reserved']) + "," + str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-delayed']) 

else:
	print '?,?,?'
