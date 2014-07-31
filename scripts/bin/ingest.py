#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       ingest.py
#
import sys
import os
import time
import magic
import hashlib
import urllib, urllib2
import re
import beanstalkc
import shutil
import uuid
import zipfile
from sanalysis3 import makefeeder
from optparse import OptionParser
from androguard.core.bytecodes import apk
from android_test import testAndroid


#Read and execute global config
sys.path.append('../config')
from config import *

__QUICK__          = False
__SILENT__         = False
__MSQUEUE__      = True

#many samples do not come with an appropriate extension, this is for adding it, if needed
FILETYPES = [{'desc' : 'Android application', 'ext': 'apk'},
             {'desc' : 'iOS application', 'ext': 'app'}]

def msbox_insert(srcfile, jobuuid, md5hash, sha256hash, fileext, target, runtime = 120, priority = beanstalkc.DEFAULT_PRIORITY):
	#all paths in lowercase
	md5hash = md5hash.lower()
	
	# copy file into malware storage directory
	destfilepath = MALWARESTORAGEBASE + '/' + srcfile
	destfile = destfilepath + '/' + sha256hash
	
	#if not os.path.exists(destfile):
	#	os.umask(0)
	#	os.makedirs(destfilepath, mode = 0777)
	#	shutil.copyfile(srcfile, destfile)
	
	#Extra check to make sure the file is there (ie. the copy worked) before we proceed
	#if not os.path.exists(destfile):
	#	return -1
	
	basefilename = os.path.basename(srcfile)
	
	# add a .seen file (timestamp on file is first seen)
#	sampletimestamp = ".seen-ms-%s-%s-%s" % (time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime()), jobuuid, basefilename)
#	seenfile = destfilepath + '/' + sampletimestamp
	# Possible race condition here...I'll take my chances
#	open(seenfile, "a").close()

	makefeeder(srcfile,sha256hash + ".xml")
	
	# Insert job into beanstalk so a vm can service it
	beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)
	beanstalk.use(BSMSBOXQ)
	print "target is" + target
	jobstring = "{'jobuuid':'%s','md5':'%s','sha256':'%s','basename':'%s','ext':'%s', 'runtime':'%d', 'target':'%s', 'fullpath':'%s'}" % (jobuuid, md5hash, sha256hash, basefilename, fileext, runtime, target,srcfile)
	jobid = beanstalk.put(jobstring, priority = priority)
	beanstalk.close()
	
	return jobid
	

def get_file_magic(filename):
	#older magic
	#ms = magic.open(magic.MAGIC_NONE)
	#ms.load()
	#filetype = ms.file(filename)
	#ms.close()
	filetype = magic.from_file(filename)
	
	#magic doesn't differentiate android from other zip files right now, so we check ourselves
	if 'Zip archive data' in filetype:
		if(testAndroid(filename)):
			filetype = "Android application"

	return filetype

def get_file_hashset(filename):
	result = {}

	filedata = open(filename).read()
	if len(filedata) > 0:
		result['md5hash']    = hashlib.md5(filedata).hexdigest()
		result['sha1hash']   = hashlib.sha1(filedata).hexdigest()
		result['sha256hash'] = hashlib.sha256(filedata).hexdigest()
		
	return result

def get_file_length(filename):
	return os.path.getsize(filename)

def get_android_target(filename):
	#maybe used androguard internal zipmodule?
	#app = apk.APK(filename, zipmodule=2)
	app = apk.APK(filename)
	version = minsdk = maxsdk = tarsdk = "0"
	minsdk = app.get_min_sdk_version();
	#maxsdk = app.get_max_sdk_version();
	tarsdk = app.get_target_sdk_version();
	
	print "min %s max %s tar %s" % (minsdk,maxsdk,tarsdk)
	ret = max(minsdk,tarsdk,maxsdk)
		
	if ret == 0:
		ret = 8
	return str(ret)
	
	
	
def main(args, options):
	global __QUICK__
	global __SILENT__
		
	if options.filename:
		filename = options.filename
	print "file: " + options.filename
	
	__QUICK__   = options.quick
	__SILENT__  = options.silent
	flagCustom  = options.custom
	jobruntime  = options.timeout
	jobpriority = options.priority
	
	filelen     = get_file_length(filename)		
	if filelen <= 0:
		return 1;
	filetype    = get_file_magic(filename)
	hashdata    = get_file_hashset(filename)
	if 'Android application' in filetype:
		target = get_android_target(filename)
	else:
		target = "notandroid" 
	
	jobuuid = str(uuid.uuid4())
	
	if not __QUICK__:
		print "FILENAME:%s" % os.path.basename(filename)
		print "JOBID:%s" % jobuuid
		print "REPORTTIME:%s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
		print "MD5:%s" % hashdata['md5hash']
		print "SHA1:%s" % hashdata['sha1hash']
		print "SHA256:%s" %	hashdata['sha256hash']
		print "FILESIZE:%d" % filelen
		print "FILETYPE:%s" % filetype
		print "SDKTARGET:%s" % target
	
		if 'Android application' in filetype:
			#do android stuff
			#extract permissions
			#determine SDK versioning	
			print "got android file"
			
			
	else:
		# this is printed only if __QUICK__ flag is set (-q or --quick)
		# if __SILENT__ is set then this is not printed
		if not __SILENT__:
			print "FILENAME:%s" % os.path.basename(filename),
			print "JOBID:%s" % jobuuid,
			print "MD5:%s" % hashdata['md5hash'],
	
	if __MSQUEUE__:
		#  Need to put some logic in here to part the filetype and set the appropriate extension
		fileext = None
		for t in FILETYPES:
			if t['desc'] in filetype:
				fileext = t['ext']
		if fileext != None:
			if 'Android application' in filetype:
				msboxjobid = msbox_insert(filename, jobuuid, hashdata['md5hash'], hashdata['sha256hash'], fileext, target, runtime = jobruntime, priority = jobpriority)
				#msboxjobid = 0
			if not __SILENT__:
				print "MSBOXJOB:%d" % msboxjobid
		else:
			if not __SILENT__:
				print "Not added to Q.  Filetype not supported."	
	return 0

if __name__ == '__main__':
	usage = "%prog [options]"
	parser = OptionParser(usage=usage)
	parser.add_option("-c", "--custom",action="store_true", dest="custom", default=False, help="Custom job (instead of malware job)")
	parser.add_option("-j", "--jobscript", action="store", type="string", metavar="FILE", dest="jobscript", default=None, help="Specify jobscript.py file (required for Custom jobs)")
	parser.add_option("-b", "--before", action="store", type="string", metavar="FILE", dest="before", default=None, help="Specify pre-processing script")
	parser.add_option("-a", "--after", action="store", type="string", metavar="FILE", dest="after", default=None, help="Specify post-processing script")
	parser.add_option("-t", "--timeout", action="store", type="int", dest="timeout", default=300, help="Specify job time in seconds (default is 300)")
	parser.add_option("-f", "--filename", action="store", type="string", metavar="FILE", dest="filename", default=None, help="Filename to ingest (required for malware jobs -- the default job type")
	parser.add_option("-p", "--priority",action="store", type="int", dest="priority", default=32768, help="Specify job priority.  Defaults to 32768.")
	parser.add_option("-q", "--quick",action="store_true", dest="quick", help="Reduce pre-processing and metadata output.")
	parser.add_option("-s", "--silent",action="store_true", dest="silent", help="Quick ingest with NO stdout output.")
	
	(options,args) = parser.parse_args()
	if len(args) > 1:
		parser.error("All options must be specified using cmdline switches")
	
	## Remove this once custom logic is written
	if options.custom:
		print "Custom jobs not yet supported by ingest.py"
		sys.exit(-1)
	if options.before or options.after:
		print "Pre/Post processing scripts not yet implemented"
		sys.exit(-1)
	
	#Set quick if silent is set
	if options.silent:
		options.quick = True
	
	## Validate options
	if options.custom:
		if (not options.jobscript) or (not os.path.isfile(options.jobscript)):
			parser.error("Valid jobscript file required for custom job")
	else:
		if options.jobscript:
			parser.error("Custom jobscript only supported with custom job")
		if (not options.filename) or (not os.path.isfile(options.filename)):
			parser.error("Valid filename file required for malware job (default job type)")
	
	main(args, options)

