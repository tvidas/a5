#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       deleteallvms.py
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


VMDELETE = "%s/android delete avd --name %s"


def delete_machine(name):
	cmd = VMDELETE % ( SDKPATH, name)
	if __DEBUG__:
		ret = subprocess.call([cmd], shell=True)
		#ret = subprocess.call([cmd],stdout="/dev/null", stderr="/dev/null", shell=True)
		#should be subprocess.DEVNULL for > 3.3
	else:
		ret = subprocess.call([cmd], shell=True)
	if not ret == 0:
		print "VM not deleted.  vmdelete returned " + str(ret)

	
def deletevms():

	#lookup from filesystem, last number
	for item in os.listdir(VMBASEDIR):
	    if os.path.isdir(os.path.join(VMBASEDIR, item)):
               	m = re.match(r"ms-sdk\d{3}-(\d{3})",item)
	 	if m :
		 print "deleteing " + item
		 delete_machine(item)

def main():

	deletevms()	

def usage(filename):
	print 'usage: %s ' % filename
	print '  deletes all sandbox VMs'
	
if __name__ == '__main__':
	
	if len(sys.argv) == 1:
		main()
	else:
		usage(sys.argv[0])
