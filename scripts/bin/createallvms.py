#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       createallvms.py
#       
import os
import sys
import time
import shutil
import subprocess
import re
from createvms import createvms

sys.path.append('../config')
from config import *

__DEBUG__ = True

def main(vmcount):
	for i in range(25):
		createvms(vmcount,i)	

def usage(filename):
	print 'usage: %s <number of vms to ADD> (for every SDKVERSION)' % filename
	
if __name__ == '__main__':
	if len(sys.argv) == 2:
		vmcount = int(sys.argv[1],10)
		if vmcount > 0:
			main(vmcount)
	else:
		usage(sys.argv[0])
