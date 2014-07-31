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
import msdb
import stat
import logging


#Read and execute global config
sys.path.append('../config')
from config import *

__QUICK__          = False
__SILENT__         = False
__MSQUEUE__      = True

#many samples do not come with an appropriate extension, this is for adding it, if needed
FILETYPES = [{'desc' : 'Android application', 'ext': 'apk'},
             {'desc' : 'iOS application', 'ext': 'app'}]

def setupLogger(name,filename):
    formatter = logging.Formatter(fmt=LOGFORMAT,datefmt=LOGDATEFORMAT)
    handler = logging.FileHandler(filename)
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger


def msbox_update(srcfile, jobuuid, md5hash, sha256hash, fileext, target, msversion, runtime = 120, priority = beanstalkc.DEFAULT_PRIORITY):
	#all paths in lowercase

	existingSubmissionId = msdb.findSubmissionToUpdate(sha256hash);

	if not existingSubmissionId:
		logger.info( "job doesn't exist!: %s" % sha256hash)
		return
	
	basefilename = os.path.basename(srcfile)

	# copy file into malware storage directory
	destfilepath = MALWARESTORAGEBASE + '/' + sha256hash 
	destfile = destfilepath + '/' + sha256hash + ".apk"
	
	if not os.path.exists(destfile):
		os.umask(0)
		os.makedirs(destfilepath, mode = 0733)
		shutil.copyfile(srcfile, destfile)

	#Extra check to make sure the file is there (ie. the copy worked) before we proceed
	if not os.path.exists(destfile):
		return -1
	
#apache can't thos this, but it doesn't need to because it's already apache
#	os.chmod(destfile,stat.S_IRUSR|stat.S_IRGRP|stat.S_IROTH)
	#3.3+ only :-( shutil.chown(destfile, "root","apache")	
	else:
		msdb.updateSample(destfile,sha256hash)
	
        if destfile == None:
                logger.info( "path to malware is empty, exiting")
                return -1

        if not existingSubmissionId:
                logger.info( "malware id is empty, exiting")
                return -1

        jobpath = MALWAREJOBSBASE +"/" + jobuuid
        if not os.path.exists(jobpath):
                os.umask(0)
                os.makedirs(jobpath, mode = 0733)


	makefeeder(destfile,jobpath +"/" + sha256hash + ".xml")
	
	# Insert job into beanstalk so a vm can service it
	beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)
	beanstalk.use(BSMSBOXQ)
	logger.info( "target is" + target)
	jobstring = "{'jobuuid':'%s','md5':'%s','sha256':'%s','basename':'%s','ext':'%s', 'runtime':'%d', 'target':'%s', 'fullpath':'%s'}" % (jobuuid, md5hash, sha256hash, basefilename, fileext, runtime, target,destfile)
	jobid = beanstalk.put(jobstring, priority = priority)
	beanstalk.close()

	msdb.updateSubmission(jobuuid,"not done","NOT ANALYZED",time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime()),"127.0.0.2",existingSubmissionId,target,runtime)

	logger.info( "dir" + os.path.dirname(destfile))

	#for DB testing, not for real ingest
	#time.sleep(3)
        #permissions_filename = sha256hash + ".xml"
        #image_used = "some vm"
        #start_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
        #msdb.updateStartRun(sha256hash,image_used,start_time,permissions_filename)

	#time.sleep(3)
        #complete_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
	#results_file = "some cool file"
 	#msdb.updateFinishRun(sha256hash,complete_time,results_file)

	
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
	
	logger.info( "min %s max %s tar %s" % (minsdk,maxsdk,tarsdk))
	ret = max(minsdk,tarsdk,maxsdk)
		
	if ret == 0:
		ret = 8
	return str(ret)
	
	
	
def main(args, options):
	global __QUICK__
	global __SILENT__
        global logger

	logger = setupLogger("root","ingestdb-web.log")
		
	if options.filename:
		filename = options.filename
	if options.inputhash:
		inputhash = options.inputhash
		logger.info( "hash: " + inputhash)

	logger.info("file: " + options.filename)
	
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

	logger.info( inputhash)
	logger.info( hashdata['sha256hash'])
	if hashdata['sha256hash'] == inputhash:
		logger.info( "hashes don't match!")


	if 'Android application' in filetype:
		target = get_android_target(filename)
	else:
		target = "notandroid" 
	
	jobuuid = str(uuid.uuid4())
	
	if not __QUICK__:
		logger.info( "FILENAME:%s" % os.path.basename(filename))
		logger.info( "JOBID:%s" % jobuuid)
		logger.info( "REPORTTIME:%s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
		logger.info( "MD5:%s" % hashdata['md5hash'])
		logger.info( "SHA1:%s" % hashdata['sha1hash'])
		logger.info( "SHA256:%s" %	hashdata['sha256hash'])
		logger.info( "FILESIZE:%d" % filelen)
		logger.info( "FILETYPE:%s" % filetype)
		logger.info( "SDKTARGET:%s" % target)
	
		#this needs to be printed because it needs to be returned to the web-ui
		print "JOBID:%s" % jobuuid
	
		if 'Android application' in filetype:
			#do android stuff
			#extract permissions
			#determine SDK versioning	
			logger.info( "got android file")
			
			
	else:
		# this is printed only if __QUICK__ flag is set (-q or --quick)
		# if __SILENT__ is set then this is not printed
		if not __SILENT__:
			logger.info( "FILENAME:%s" % os.path.basename(filename))
			logger.info( "JOBID:%s" % jobuuid)
			logger.info( "MD5:%s" % hashdata['md5hash'])
	
			#this needs to be printed because it needs to be returned to the web-ui
			print "JOBID:%s" % jobuuid
	
	if __MSQUEUE__:
		#  Need to put some logic in here to part the filetype and set the appropriate extension
		fileext = None
		for t in FILETYPES:
			if t['desc'] in filetype:
				fileext = t['ext']
		if fileext != None:
			if 'Android application' in filetype:
				msboxjobid = msbox_update(filename, jobuuid, hashdata['md5hash'], hashdata['sha256hash'], fileext, target, MSVERSION, runtime = jobruntime, priority = jobpriority)
				#msboxjobid = 0
			if not __SILENT__:
				logger.info( "MSBOXJOB:%d" % msboxjobid)
		else:
			if not __SILENT__:
				logger.info( "Not added to Q.  Filetype not supported."	)
	return 0

if __name__ == '__main__':
	usage = "%prog [options]"
	parser = OptionParser(usage=usage)
	parser.add_option("-c", "--custom",action="store_true", dest="custom", default=False, help="Custom job (instead of malware job)")
	parser.add_option("-j", "--jobscript", action="store", type="string", metavar="FILE", dest="jobscript", default=None, help="Specify jobscript.py file (required for Custom jobs)")
	parser.add_option("-b", "--before", action="store", type="string", metavar="FILE", dest="before", default=None, help="Specify pre-processing script")
	parser.add_option("-a", "--after", action="store", type="string", metavar="FILE", dest="after", default=None, help="Specify post-processing script")
	parser.add_option("-t", "--timeout", action="store", type="int", dest="timeout", default=300, help="Specify job time in seconds (default is 300)")
	parser.add_option("-H", "--hash", action="store", type="string", dest="inputhash", default=None, help="the hash that will be looked up in the DB, for web submissions")
	parser.add_option("-f", "--filename", action="store", type="string", metavar="FILE", dest="filename", default=None, help="Filename to ingest (required for malware jobs -- the default job type")
	parser.add_option("-p", "--priority",action="store", type="int", dest="priority", default=32768, help="Specify job priority.  Defaults to 32768.")
	parser.add_option("-q", "--quick",action="store_true", dest="quick", help="Reduce pre-processing and metadata output.")
	parser.add_option("-s", "--silent",action="store_true", dest="silent", help="Quick ingest with NO stdout output.")
	
	(options,args) = parser.parse_args()
	if len(args) > 1:
		if parser.filename and parser.inputhash :
			logger.info( "looks like a web submission")
		else:
			parser.error("All options must be specified using cmdline switches")
	
	## Remove this once custom logic is written
	if options.custom:
		logger.info( "Custom jobs not yet supported by ingest.py")
		sys.exit(-1)
	if options.before or options.after:
		logger.info( "Pre/Post processing scripts not yet implemented")
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

