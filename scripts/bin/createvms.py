#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       createvms.py
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
DEFAULTSDK = "8"

#emulator default sdcard size, in MB
VMSDCARD = 100


#we do not create VMs on the fly, we maintain pools of VMs to select from, this lends to using hardware as well
VMCREATE = "/bin/echo 'no' | %s/android create avd -n %s -t %s --path %s/%s -c %dM"
#VMCREATE = "%s/android create avd -n %s -t %s --path %s/%s -c %dM"
#VMDELETE = "./android delete avd --name test2"
#VMDELETE = "./android delete avd --name %s"


def create_machine(index,target):

	#note, target for api 8 is "android-8" if you put 8, it will be the 8th target in the list of "android list targets"
	name = "ms-sdk" + str(target).zfill(3) + "-" + str(index).zfill(3)
	print "creating %s" % name
	cmd = VMCREATE % ( SDKPATH, name, "android-" + str(target), VMBASEDIR, name,  VMSDCARD)
	#cmd = VMCREATE % ( SDKPATH, name, str(target), VMBASEDIR, name,  VMSDCARD)
	if __DEBUG__:
		ret = subprocess.call([cmd], shell=True)
		#ret = subprocess.call([cmd],stdout="/dev/null", stderr="/dev/null", shell=True)
		#should be subprocess.DEVNULL for > 3.3
	else:
		ret = subprocess.call([cmd], shell=True)
	if not ret == 0:
		print "VM not created.  vmcreate returned " + str(ret)
		print "command was %s" % cmd

	
def createvmsrange(startidx,endidx,target):
	for i in range (startidx,endidx+1):
		create_machine(i,target)
	return 0

def createvms(vmcount,target):
        lastvm = get_lastvm()
        if lastvm == None:
                print 'Error getting current VM count'
                sys.exit(-1)

        rangestart = lastvm + 1
        rangeend   = lastvm + vmcount

        createvmsrange(rangestart, rangeend, target)



def get_lastvm():
	lastvm = 0

	#lookup from filesystem, last number
	for item in os.listdir(VMBASEDIR):
	    if os.path.isdir(os.path.join(VMBASEDIR, item)):
               	m = re.match(r"ms-sdk\d{3}-(\d{3})",item)
	 	if m :
		 #print item
		 #print m.group(1)
	   	 if lastvm < int(m.group(1)):
			lastvm = int(m.group(1))
			#print "last is " + str(lastvm)

	return lastvm

def main(vmcount,target):

	createvms(vmcount,target)	
	#just adds vms to the end of the count...does not fill in the blanks
	#lastvm = get_lastvm()
	#if lastvm == None:
	#	print 'Error getting current VM count'
	#	sys.exit(-1)
	
	#rangestart = lastvm + 1
	#rangeend   = lastvm + vmcount
	

def usage(filename):
	print 'usage: %s <number of vms to ADD> [<sdk version (defaults to "android-8")>]' % filename
	
if __name__ == '__main__':
	if len(sys.argv) == 3:
		vmcount = int(sys.argv[1],10)
		vmsdk = int(sys.argv[2],10)
		#should probably check for valid sdk version...
		if vmcount > 0 and vmsdk > 0:
			main(vmcount,vmsdk)
	elif len(sys.argv) == 2:
		vmcount = int(sys.argv[1],10)
		if vmcount > 0:
			main(vmcount,DEFAULTSDK)
	else:
		usage(sys.argv[0])
