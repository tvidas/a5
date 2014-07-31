#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       listvms.py
#       
import os
import sys
import time
import shutil
import subprocess
import re

sys.path.append('../config')
from config import *

__DEBUG__ = True


def listvms():

	#lookup from filesystem, last number
	for item in os.listdir(VMBASEDIR):
	    if os.path.isdir(os.path.join(VMBASEDIR, item)):
               	m = re.match(r"ms-sdk\d{3}-(\d{3})",item)
	 	if m :
		 print str(item)

def main():

	listvms()	

def usage(filename):
	print 'usage: %s' % filename
	print '  lists all sandbox VMs'
	
if __name__ == '__main__':
	
	if len(sys.argv) == 1:
		main()
	else:
		usage(sys.argv[0])

