#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       deletealljobs.py


import beanstalkc
from pprint import pprint

#Read and execute global config
sys.path.append('../config')
from config import *


beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)


pprint(beanstalk.stats_tube(BSMSBOXQ))

beanstalk.use(BSMSBOXQ)
beanstalk.watch(BSMSBOXQ)

hasnext = beanstalk.peek_ready()
while hasnext:
	job = beanstalk.reserve()
	job.delete()
	hasnext = beanstalk.peek_ready()

pprint(beanstalk.stats_tube(BSMSBOXQ))

