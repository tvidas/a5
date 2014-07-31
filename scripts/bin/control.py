#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   requires:
#     beanstalkc
#     PyYaml
#       
# Update /etc/sysctl.conf to keep the arp entries from timing out
# ARP cache entry timeout
# net.ipv4.neigh.default.gc_stale_time = 3600
#
import os
import sys
import time
import signal
import struct
import fcntl
import socket
import shutil
import re
import subprocess
import beanstalkc
import syslog
import pprint
import random
import shlex
import traceback
from pwd import getpwnam
from grp import getgrnam
import multiprocessing 
from lxml import etree
import msdb
import libIntent
import logging

#Read and execute global config
#exec open('/opt/ms/config/config.py').read()
sys.path.append('../config')
from config import *

#this is global and will be assigned early in main
logger = None

class Consumer(multiprocessing.Process):
    
    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        proc_name = self.name
        while True:
            next_task = self.task_queue.get()
            if next_task is None:
                # Poison pill means we should exit
                logger.info( '%s: Exiting' % proc_name)
                break
            logger.info( '%s: %s' % (proc_name, next_task))
            answer = next_task()
            self.result_queue.put(answer)
        return


class Task(object):
    def __init__(self, a, b):
        self.a = a
        self.b = b
    def __call__(self):
        time.sleep(0.1) # pretend to take some time to do our work
        return '%s * %s = %s' % (self.a, self.b, self.a * self.b)
    def __str__(self):
        return '%s * %s' % (self.a, self.b)

class ActivePool(object):
    def __init__(self):
        super(ActivePool, self).__init__()
        self.mgr = multiprocessing.Manager()
        self.active = self.mgr.list()
        self.lock = multiprocessing.Lock()
    def makeActive(self, name):
        with self.lock:
            self.active.append(name)
    def makeInactive(self, name):
        with self.lock:
            self.active.remove(name)
    def __str__(self):
        with self.lock:
            return str(self.active)


__DEBUG__ = True

#number of children workers to spawn
# could be multiprocessing.cpu_count() - 1
NUMWORKERS = 5
NUMACTIVEWORKERS = 5
ADBPORT = 5554
PSIZE = 128
ADBTRIES = 10


VM_POLL_REST = 7

#TODO used commands like this to give helpful error messages when avd create fails
#"android update sdk --no-ui" 
#"android list sdk" 
#"./android update sdk --no-ui -n --filter 1,2,11" (2.2, plus tools) 
#"./android list targets"

#emulator default sdcard size, in MB
VMSDCARD = 100


#no reason to do anything if we can't get to adb or emulator
if not os.path.isfile(SDKPATH + "/emulator"):
	logger.info( "can't find emulator at %s" % SDKPATH)
if not os.path.isfile(ADBPATH + "/adb"):
	logger.info( "can't find adb at %s" % ADBPATH)


#Globals
beanstalk = None
ADBFAILCOUNT = None
#beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)
#beanstalk.watch(BSMSBOXQ)
#beanstalk.use(BSMSBOXQ)
#beanstalk.ignore('default')

class AVM(object):
    def __init__(self, name, path, state, version):
	self.name = name
	self.path = path
	self.state = state
	self.version = version
    def setVersion(self, v):
	self.state = v 
    def setState(self, state):
	self.state = state


#setup syslog output - this is where we will write all messages
#syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID, syslog.LOG_DAEMON)
syslog.openlog("MS", syslog.LOG_PID, syslog.LOG_DAEMON)

#global flag to signal termination.  No need for event.
flagTerminate = False

def sigint_handler(signal, frame):
	global flagTerminate
	syslog.syslog('Caught SIGINT - Waiting for %d active jobs to terminate...' % len(assignments))
	flagTerminate = True

def formatExceptionInfo(maxTBlevel=5):
         cla, exc, trbk = sys.exc_info()
         excName = cla.__name__
         try:
             excArgs = exc.__dict__["args"]
         except KeyError:
             excArgs = "<no args>"
         excTb = traceback.format_tb(trbk, maxTBlevel)
         return (excName, excArgs, excTb)

def get_VMs(VMs):
        #lookup from filesystem
        #VMs[2] = avm({"name": "ms-vm002", "path": "some/path/", "state": "Off", "version": "5"})
        for item in os.listdir(VMBASEDIR):
            if os.path.isdir(os.path.join(VMBASEDIR, item)):
                m = re.match("ms-sdk(\d{3})-\d{3}",item)
                if m :
                 logger.info( item)
                 logger.info( m.group(1))
		 d = {"name": m.group(0), "path": os.path.join(VMBASEDIR, item), "state": "Off", "version": m.group(1)}
		 VMs[m.group(0)] = AVM(**d)
		 #VMs[m.group(0)] = (avm({"name": m.group(0), "path": os.path.join(VMBASEDIR, item), "state": "Off", "version": m.group(1)}))

def list_VMs(VMs):
	logger.debug("---VMList---")
	for i in VMs.keys():
		logger.debug( "%s %s %10s %s " % (VMs[i].name, VMs[i].path, VMs[i].state, VMs[i].version))
	logger.debug("------------")
	for i in VMs.keys():
		if VMs[i].state != "Off":
			logger.info( "%s %s %10s %s " % (VMs[i].name, VMs[i].path, VMs[i].state, VMs[i].version))

def kick_adb():
	name = multiprocessing.current_process().name
	ADBKICK = "%s/adb kill-server"
	#whatever the next issue of adb is, it will automatically start the server again
	cmd = ADBKICK % ( ADBPATH )
	logger.info( name + ":" + cmd)
	try:
		args = shlex.split(cmd)
		pKick = subprocess.Popen(args)
		pKick.terminate()
	except:
		logger.info( name + ":" + "adb kick error", sys.exc_info()[0])

def kick_adb_maybe(adbl,fcnt):
	with adbl:
		fcnt.value += 1
		if fcnt.value > 20:
			fcnt.value = 0
			kick_adb()
		

def find_key(dic, val):
	"""return the key of dictionary dic given the value"""
	return [k for k, v in dic.iteritems() if v == val][0]

def error_log(msg):
	logmsg = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime()) + ' : ' + msg
	logger.info( logmsg)
	syslog.syslog(logmsg)

def updateStatus(workers,alive,dead):
	f = open('ms-status.csv','w')
	f.write("%s,%s,%s" % (workers,alive,dead))
	f.close()


def runInVM(m,job,VMs,adbport,vmlock,adbl,results, fcnt):
	name = multiprocessing.current_process().name

 	formatter = logging.Formatter(fmt=LOGFORMAT,datefmt=LOGDATEFORMAT)
    	pathForFile = MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256'] + "-run.log"
	print "HH%sHH" % pathForFile
    	handler = logging.FileHandler(pathForFile, mode='w')
    	handler.setFormatter(formatter)

    	vlogger = logger.getChild("worker" + name + ".vm")
    	vlogger.setLevel(logging.DEBUG)
    	vlogger.addHandler(handler)

	vlogger.info("logging started at " + pathForFile)


	rval = True
	if VMs[m].state in ["Reserved"] :
		with vmlock:
			VMlocal = VMs[m];
			VMlocal.state = "Starting"
			VMs[m] = VMlocal;
		#emulator doens't observe system hosts:  (must start emulator with -partition-size 128 (for example) to give room to write)
		#adb pull /etc/hosts
		#edit to 10.0.2.2 (your local machine)
		#adb remount
		#adb push hosts /etc/hosts
		t1 = time.time()
		

		#emulator -avd NAME -partition-size 128 -ports 5,2322 -no-window -tcpdump FILE -dns-server SERVER -http-proxy PROXY
		#TODO instead of wipe-data, would be best to re-create the VM
		EMUSTART = "%s/emulator -avd %s -partition-size %s -port %s -no-window -tcpdump %s -wipe-data"
		#./adb logcat
		#./adb install /storage/malware/RU.apk
		#./adb shell am broadcast -a android.intent.action.BOOT_COMPLETED

		#start (with specified ports)
		#emulator -ports X,Y @avd_X

		#wait for emulator to be fully started
		#./adb -s emulator-5584 wait-for-device
		EMUWAIT = "%s/adb -s %s wait-for-device"

		EMULOGCAT = "%s/adb -s %s logcat"

		#command
		#adb -s emualtor-X shell cmd

		EMUINSTALL = "%s/adb -s %s install %s"

		#<INTENT> specifications include these flags:
		#       [-a <ACTION>] [-d <DATA_URI>] [-t <MIME_TYPE>]
		#       [-c <CATEGORY> [-c <CATEGORY>] ...]
		#       [-e|--es <EXTRA_KEY> <EXTRA_STRING_VALUE> ...]
		#       [--esn <EXTRA_KEY> ...]
		#       [--ez <EXTRA_KEY> <EXTRA_BOOLEAN_VALUE> ...]
		#       [-e|--ei <EXTRA_KEY> <EXTRA_INT_VALUE> ...]
		#adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -c android.intent.category.HOME -n net.fstab.checkit_android/.StartupReceiver
		#am broadcast -a android.intent.action.BOOT_COMPLETED
		EMUINTENT = "%s/adb -s %s shell am broadcast -a %s"
	
		#adb shell am start -n com.package.name/com.package.name.ActivityName
		#am start -a android.intent.action.MAIN -n com.iftitah.android.contact/com.iftitah.android.contact.Contact
		#am start -a <ACTION> -n <PACKAGE>/<PACKAGE><ACTIVITYCLASS>
		EMULAUNCH = "%s/adb -s %s shell am start -a %s -n %s/%s"

		#kill
		#could do adb shell stop
		#but why really?  just going to reset for next run anyway
		# (though a stop would preserve state)
		#adb -s emulator-X emu kill
		EMUKILL = "%s/adb -s %s emu kill"

		#monkey
		#$ adb shell monkey -v -p your.package.name 100 --ignore-security-exceptions -s SEED
		EMUMONKEY = "%s/adb -s %s shell monkey -v -p %s 100 --ignore-security-exceptions -s %s --throttle 250"

		#update database with start values
		permissions_filename = job['sha256'] + ".xml"
		image_used = VMs[m].name
		start_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
		msdb.updateStartRun(job['jobuuid'],image_used,start_time,permissions_filename,MSVERSION)

		vlogger.info( name + ":" + "...starting VM " + VMs[m].name)
		#start it
		cmd = EMUSTART % ( SDKPATH, VMs[m].name, PSIZE, str(adbport), MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256']+ "-orig.pcap")
		vlogger.info( name + ":" + cmd)
		pEmu = None
		try:
			args = shlex.split(cmd)
			pEmu = subprocess.Popen(args)
		except:
			vlogger.info( name + ":" + "emulator start error", sys.exc_info()[0])
			sys.exit(1)
		#check for start error conditions:
		#emulator: WARNING: ignoring locked SD Card image at /path/to/avd/ms-sdk003-003/sdcard.img
		#it seems too many emulator instances are running on this machine. Aborting


		#wait for it to start
		cmd = EMUWAIT % ( ADBPATH, "emulator-" + str(adbport))
		vlogger.info( name + ":" + cmd)
		try:
			ret = subprocess.check_call([cmd], shell=True)
			vlogger.info( name + ":" + "emulator wait returned: %d" % ret )
		except:
			vlogger.error( name + ":" + "emulator wait error: %s" % cmd )
			sys.exit(1)
		vlogger.info( name + ":" + "emulator-" + str(adbport) + " started")
		time.sleep(VM_POLL_REST * 3)
		with vmlock:
			VMlocal = VMs[m];
			VMlocal.state = "Running"
			VMs[m] = VMlocal;

		#start logcat
		#start it
		cmd = EMULOGCAT % ( SDKPATH, "emulator-" + str(adbport))
		vlogger.info( name + ":" + cmd)
		pLogCat = None
		fLogCat = None
		try:
			args = shlex.split(cmd)
			vlogger.info( args)
			fLogCat = open(MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256'] + ".logcat","w")
			fNull = open("/dev/null")
#TODO			pLogCat = subprocess.Popen(args, stdin=fNull, stderr=fNull, stdout=fLogCat)
		except:
			vlogger.error( name + ": " + cmd )
			vlogger.error( formatExceptionInfo())
			vlogger.error( name + ":" + "emulator logcat error", sys.exc_info()[0])
			sys.exit(1)

		#install malicious app
		cmd = EMUINSTALL % ( ADBPATH, "emulator-" + str(adbport), "'" + job['fullpath'] + "'")
		vlogger.info( name + ":" + cmd)
	
		try:
			ret = subprocess.check_output([cmd], shell=True)
			vlogger.info( name + ":" + "emulator install returned: %s" % ret )
			install_attempts = ADBTRIES
			while "Success" not in ret and install_attempts > 0:
				kick_adb_maybe(adbl, fcnt)
				vlogger.info( name + ":" + "install failed emulator install returned: %s" % ret )
				time.sleep(VM_POLL_REST)

				#TODO FIXME, track down why this sometimes stalls forever, seem on SDKs 11 and 14...
				ret = subprocess.check_output([cmd], shell=True)
				install_attempts -= 1
				if install_attempts <= 0:
					syslog.syslog(VMs[m].name + ":" + "install failed emulator install returned: %s" % ret )
					vlogger.error(VMs[m].name + ":" + "install failed emulator install returned: %s" % ret )
				

		except:
			vlogger.error( name + ":" + "emulator install fatal error: %s" % cmd )
			vlogger.error( formatExceptionInfo())
			sys.exit(1)

		#possible errors:
		#Error: Could not access the Package Manager.  Is the system running?

		time.sleep(VM_POLL_REST * 3)

		#stimulate
		doc = etree.parse( MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256'] + ".xml")
		package = doc.find('package')

		
		li = libIntent.libIntent("localhost",adbport)
	
		#for each rint
		for rint in doc.findall('rint'):
			vlogger.info( name + " handling " + str(rint.text))
			li.handleRIntent(str(rint.text))

		#for each permission (actions and rints _should_ catch all these....)
		for perm in doc.findall('permission'):
			vlogger.info( name + " handling " + str(perm.text))
			li.handlePermission(str(perm.text))

		#for each action
		for action in doc.findall('action'):
			vlogger.info( name + " handling " + str(action.text))
			li.handleAction(str(action.text))
			#BROADCASTS are done this way
			#cmd = EMUINTENT % ( ADBPATH, "emulator-" + str(adbport), "android.intent.action.BOOT_COMPLETED")
			cmd = EMUINTENT % ( ADBPATH, "emulator-" + str(adbport), str(action.text))
			vlogger.info( name + ":" + cmd)
			try:
				#TODO check for "Broadcast completed" in output, repeat if necessary
				ret = subprocess.check_call([cmd], shell=True)
			except:
				syslog.syslog("app %s error sending intent %s" % (job['sha256'],str(action.text)))
				vlogger.error( name + ":" + "emulator intent error: %s" % cmd )
				vlogger.error( name + ":" + "emulator intent error: %d" % ret )
				#TODO exit is a little too harsh here, but should probably requeue somehow
				#sys.exit(1)
				#sys.exit(1)

		#somethings just don't have nice rint or actions
		li.sendCall()
		time.sleep(VM_POLL_REST)
		li.endAllCalls()

		#open app


		# TODO this should not be a for/for loop, the actions shoudl be paired with activities
		for activity in doc.findall('activity'):
			for action in doc.findall('action'):
				vlogger.info( name + ": " + "################## launching activity " + str(activity.text))
				cmd = EMULAUNCH % ( ADBPATH, "emulator-" + str(adbport), str(action.text), str(package.text), str(activity.text))
				vlogger.info( name + ":" + cmd)
				try:
					ret = subprocess.check_call([cmd], shell=True)
				except:
					vlogger.error( name + ":" + "emulator launch error: %s" % cmd )
					vlogger.error( name + ":" + "emulator launch error: %d" % ret )
					#TODO exit is a little too harsh here, but should probably requeue somehow
					#sys.exit(1)

		time.sleep(VM_POLL_REST * 5)

		#monkey around
		cmd = EMUMONKEY % ( ADBPATH, "emulator-" + str(adbport), str(package.text), random.randint(1,100))
		vlogger.info( name + ":" + cmd)
	
		try:
			ret = subprocess.check_output([cmd], shell=True)
			vlogger.info( name + ":" + "emulator monkey returned: %s" % ret )
#			monkey_attempts = ADBTRIES
#			while "Success" not in ret and monkey_attempts > 0:
#				kick_adb_maybe(adbl, fcnt)
#				vlogger.info( name + ":" + "monkey failed emulator monkey returned: %s" % ret )
#				time.sleep(VM_POLL_REST)
#
#				ret = subprocess.check_output([cmd], shell=True)
#				monkey_attempts -= 1
#				if monkey_attempts <= 0:
#					syslog.syslog(VMs[m].name + ":" + "monkey failed emulator monkey returned: %s" % ret )
				

		except:
			vlogger.error( name + ":" + "emulator monkey fatal error: %s" % cmd )
			syslog.syslog(VMs[m].name + ":" + "monkey failed emulator monkey error: %s" % cmd )
			vlogger.error( formatExceptionInfo())
			sys.exit(1)

		#kill
		cmd = EMUKILL % ( ADBPATH, "emulator-" + str(adbport))
		vlogger.info( name + ":" + cmd)
		try:
			ret = subprocess.check_call([cmd], shell=True)
		except:
			vlogger.error( name + ":" + "emulator kill error")
			sys.exit(1)

		#cleanup
		if pEmu.poll() is not None:
			vlogger.info( name + ": " + "poll is " + str(pEmu.poll()))
			try:	
				pEmu.terminate()
			except:
				vlogger.error( name + ": " + "pEmu term failed")
#TODO		if pLogCat.poll() is not None:
#TODO			pLogCat.terminate()
		fLogCat.flush()
		fLogCat.close()
		fNull.close()
		
		time.sleep(VM_POLL_REST)
		vlogger.info( name + ":" + "...stopping VM " + VMs[m].name)
		with vmlock:	
			VMlocal = VMs[m];
			VMlocal.state = "Off"
			VMs[m] = VMlocal;
	
		t2 = time.time()	

		complete_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
		results_file = job['sha256'] + ".pcap"
		msdb.updateFinishRun(job['jobuuid'],complete_time,results_file)

		#post process pcap, pretty crude for now, adb uses it's port and port+1; so two prunes
		#...and it seems that adb uses 5555 regardless of which even port is specified
		originalpcap = MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256'] + "-orig.pcap"
		tmppcap = MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256'] + "-temp.pcap"
		finalpcap = MALWAREJOBSBASE + "/" + job['jobuuid'] + "/" + job['sha256'] + ".pcap"

		#cmd = "prune_pcap.sh %s %s %s" % (os.path.dirname(job['fullpath']) + "/" + job['sha256']+ "-orig.pcap",os.path.dirname(job['fullpath']) + "/" + job['sha256']+ ".pcap", str(adbport))
		cmd = "prune_pcap.sh %s %s %s" % (originalpcap,tmppcap, str(adbport))
		vlogger.info( name + ":" + cmd)
		try:
			ret = subprocess.check_call([cmd], shell=True)
		except:
			vlogger.error( name + ":" + "pcap prune error")
			sys.exit(1)

		#cmd = "prune_pcap.sh %s %s %s" % (os.path.dirname(job['fullpath']) + "/" + job['sha256']+ "-orig.pcap",os.path.dirname(job['fullpath']) + "/" + job['sha256']+ ".pcap", str(int(adbport)+1))
		cmd = "prune_pcap.sh %s %s %s" % (tmppcap,finalpcap, str(int(adbport)+1))
		vlogger.info( name + ":" + cmd)
		try:
			ret = subprocess.check_call([cmd], shell=True)
		except:
			vlogger.error( name + ":" + "pcap prune error")
			sys.exit(1)

		#cmd = "prune_pcap.sh %s %s %s" % (os.path.dirname(job['fullpath']) + "/" + job['sha256']+ "-orig.pcap",os.path.dirname(job['fullpath']) + "/" + job['sha256']+ ".pcap", str(5555))
#		cmd = "prune_pcap.sh %s %s %s" % (originalpcap,finalpcap, str(adbport))
#		vlogger.info( name + ":" + cmd)
#		try:
#			ret = subprocess.check_call([cmd], shell=True)
#		except:
#			vlogger.error( name + ":" + "pcap prune error")
#			sys.exit(1)

		#TODO unique ip addresses
		#tshark -r <input.pcap> -T fields -e ip.dst ip.src | sort | uniq


		vlogger.info( name + ":" + "sample took %s seconds process" % str(t2 - t1))
		results.put(t2-t1)

	elif VMs[m].state in ["Off"]:
		vlogger.info( name + ":" + VMs[m].name + "run error: found in state OFF!")
		rval = False
	elif VMs[m].state in ["Ready"]:
		vlogger.info( name + ":" + VMs[m].name + "run error: is running and not available for new malware")
		rval = False
		#if m.name in assignments:
		#	if assignments[m.name]['timeout'] <= time.time():
		#		#do anything you want to wrap up
		#		job_post_process(m)
		#		job_cleanup(m)
		#		vm_poweroff(m)
		#else: # if the machine is running but there is no job assigned to it then kill it
		#	pcap_terminate(m)
		#	vm_poweroff(m)
#	else: #not sure this is relevant...may need to remove it
#		vm_poweroff(m) #I need to get a list of states that I want to poweroff by default
	return rval

def findCompatibleVM(job,VMs,vml):
	rval = None	
	with vml:
		#logger.info( "   ...uuid is " + job['jobuuid'])
		#logger.info( "   ...app target is " + str(job['target']))
		for m in VMs.keys():
			#logger.info( "   seeing if " + VMs[m].name + " is compat...")
			#logger.info( "   ...version is " + str(int(VMs[m].version)) + " ...")
	#		#Don't process machines without the ms naming convention
	#		if not re.match('ms-vm\d{3}',VMs[m].name):
	#			continue


			#if the AndroidManifest doesn't havd a minsdk, maxsdk or targetsdk, then we don't know anything
			#about what version the app was created for, so we randomly pick something
			#if we pick "wrong" for our VM set, the job will just get delayed and we'll pick something else later

			targetsdk = int(job['target'])
			if targetsdk == 0:
				targetsdk = random.randint(MINSDKVER,MAXSDKVER)
				syslog.syslog("app %s didn't specify any sdk information selecting %s" % (job['sha256'],targetsdk))
				

	# states are Off=not powered on, Ready=powered on and ready for malware, Running=currently running (some other) malware, reserved=found, but not on yet
			if VMs[m].state in ["Off"] and int(VMs[m].version) == targetsdk:
				if not flagTerminate: #Dont assign more jobs if we are terminating
					logger.info( VMs[m].name + " (" + str(m) + ") is available")
					VMlocal = VMs[m];
					VMlocal.setState("Reserved")
					VMs[m] = VMlocal;
					
					rval = m
					break
					#job_assign(m) #vm is started at end of job assignment
					#Uncomment the next time to debug one job at a time
					#flagTerminate = True
			elif VMs[m].state in ["Running"]:
				v = 1
				#logger.info( VMs[m].name + " is running and not available for new malware")
				#if m.name in assignments:
				#	if assignments[m.name]['timeout'] <= time.time():
				#		#do anything you want to wrap up
				#		job_post_process(m)
				#		job_cleanup(m)
				#		vm_poweroff(m)
				#else: # if the machine is running but there is no job assigned to it then kill it
				#	pcap_terminate(m)
				#	vm_poweroff(m)
	#		else: #not sure this is relevant...may need to remove it
	#			vm_poweroff(m) #I need to get a list of states that I want to poweroff by default
	return rval

def rebeanstalk():
	global beanstalk
	if not beanstalk:
		error_log('Re-establishing connection to beanstalkd')
		beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)
		beanstalk.watch(BSMSBOXQ)
		beanstalk.use(BSMSBOXQ)
		beanstalk.ignore('default')


def worker(s, pool, q, str1, VMs, vml, adbport, count, adbl, results, fcnt):
    #global assignments
    global beanstalk

    name = multiprocessing.current_process().name

    formatter = logging.Formatter(fmt=LOGFORMAT,datefmt=LOGDATEFORMAT)
    handler = logging.FileHandler("worker.log")
    handler.setFormatter(formatter)

    wlogger = logger.getChild("worker" + name)
    wlogger.setLevel(logging.DEBUG)
    wlogger.addHandler(handler)

    with s:
        pool.makeActive(name)
	while True:
		#funky kill pill
		content = q.get()
		q.put(content)
        	if content == "die":
			wlogger.info( name + ":" + " is committing suicide")
			pool.makeInactive(name)
			sys.exit(0)
		else:
			#logger.info( 'Now running: %s %s %s (%s)' % (str(pool), str1, content,adbport))
			wlogger.info( name + ":" + " is working...")

			#check for a job in the beanstalk Q
			#if not beanstalk:
			#	error_log('Re-establishing connection to beanstalkd')
			#	beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)
			#	beanstalk.watch(BSMSBOXQ)
			#	beanstalk.use(BSMSBOXQ)
			#	beanstalk.ignore('default')
			rebeanstalk()

			#all this checking is just "best effort" another thread may still reserve first
			if BSMSBOXQ not in beanstalk.tubes():
					wlogger.info( name + ":" + "there are no samples in the beanstalk")
			else:
				arejobs = beanstalk.peek_ready()
				if arejobs is None:
					wlogger.info( name + ":" + "there are no samples ready in the beanstalk")
					time.sleep(VM_POLL_REST)
				else:

					#we want to reserve, not peak_ready because if we can't process, we want to release with a delay later
					beansalkjob = None
					try:
						beanstalkjob = beanstalk.reserve()
					except:
						wlogger.info( name + ": " + "beanstalk reserve error, probably out of jobs")

					#if there was a job and we got it then queue up analysis
					job = None
					if beanstalkjob:
						try:
							job = eval(beanstalkjob.body)
						except:
							error_log('ERROR: could not eval job - invalid job')
							beanstalkjob.delete()
							wlogger.info( name + ":" + "BAD JOB, deleting")
							#return False
							continue
						if job:
							#is there a VM compatible with this sample that is ready to be used?
							m = findCompatibleVM(job,VMs,vml)
							if m is not None:
								#wlogger.info( name + ":" + "using VM " + str(m))
								wlogger.info( name + ":" + "using VM " + str(m) + " for " + job['basename'] + "(" + job['target'] + ")")
								#process sample

								#TODO this delete should really only happen if runInVM succeeds
								beanstalkjob.delete()
								if runInVM(m,job,VMs,adbport,vml,adbl,results, fcnt):
									#runInVM might take a while
									rebeanstalk()
									#delete from BSqueue if successfull
									#beanstalkjob.delete()
									count.value += 1
							
								#should never hit this due to live/die toggle		
								if flagTerminate:
									wlogger.info( name + ":" + "terminating?!")
									sys.exit(0)
								else:
									continue

								#put back into VMready Q
							else:
								#no VM found, put it back in the queue (nobody will process for 60 seconds
								beanstalkjob.release(delay=BSDELAY)
								wlogger.info( name + ":" + "requeuing job requiring a target version " + job['target'])
			#time.sleep(VM_POLL_REST)

def setupLogger():
    formatter = logging.Formatter(fmt=LOGFORMAT,datefmt=LOGDATEFORMAT)
    handler = logging.FileHandler(LOGFILE)
    handler.setFormatter(formatter)

    logger = logging.getLogger() #must not specify a name in order to grab module logs
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger

def main():
	global flagTerminate
        global beanstalk
	global logger

	logger = setupLogger()

 	# define a Handler which writes INFO messages or higher to the sys.stderr
	console = logging.StreamHandler()
	console.setLevel(logging.INFO)
	# set a format which is simpler for console use
	formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
	# tell the handler to use this format
	console.setFormatter(formatter)
	# add the handler to the root logger
	logging.getLogger().addHandler(console)

	random.seed()

	pool = ActivePool()
	assignments = pool.mgr.dict()
	count = pool.mgr.Value('i', 0)
	ADBFAILCOUNT = pool.mgr.Value('i', 0)

	VMs = pool.mgr.dict()

	s = multiprocessing.Semaphore(NUMACTIVEWORKERS)
	q = multiprocessing.Queue()
	r = multiprocessing.Queue()
	results = []
	al = multiprocessing.RLock()
	vml = multiprocessing.RLock()
	cl = multiprocessing.RLock()

	get_VMs(VMs)
	list_VMs(VMs)
	#make sure any pcaps are killed and we are starting with a clean filesystem

	for i in range(30):
		#q.put("item " + str(i) + " content")
		q.put("live" + str(i))
		

	#adb ports are 5554 - 5584, only even	
	port = ADBPORT
	jobs = [
		multiprocessing.Process(target=worker, name=str(i), args=(s, pool, q, "hi", VMs, vml, str(port+(i*2)), count, al, r, ADBFAILCOUNT))
		for i in range(NUMWORKERS)
		]

	for j in jobs:
		logger.info( "starting worker %s" % j.name)
		j.start()

#	for j in jobs:
#		j.join()
#		logger.info( 'Now running: %s' % str(pool))

	#make the connection after the child spawning, each child makes thier own connections
	rebeanstalk()

	while True:

		logger.info( "==============================")
		logger.info( "processed %d samples so far" % count.value)
		try:
			#not great, but the parent is the only consumer of r items
			thing = r.get(block=False)
			results.append(thing)
		except:
			logger.warning( "results queue exception")
		
		if len(results) > 0:
			logger.info( "average sample time: %s" % str(sum(results) / float(len(results))))
		try:
			if BSMSBOXQ not in beanstalk.tubes():
					logger.info( "there are no samples in the beanstalk")
			else:
				if beanstalk.peek_ready() is not None:
					logger.info( str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-ready']) + " samples ready to process")
				else:
					logger.info( "0 samples ready to process")
				if beanstalk.peek_reserved() is not None:
					logger.info( str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-reserved']) + " samples are processing")
				else:
					logger.info( "0 samples are processing")
				if beanstalk.peek_delayed() is not None:
					logger.info( str(beanstalk.stats_tube(BSMSBOXQ)['current-jobs-delayed']) + " samples are delayed")
				else:
					logger.info( "0 samples are delayed")
		except KeyError:
			logger.warning( "beanstalk keyerror")
		except:
			logger.warning( "beanstalk general error")
		logger.info( "about " + str(q.qsize()) + " current q items")
		logger.info( "adb has failed " + str(ADBFAILCOUNT.value) + " times since last kick")
		logger.debug( "should be " + str(NUMWORKERS) + " processes:")
		walive = 0
		wdead = 0
		for j in jobs:
			if j.is_alive():
				logger.debug( "   " + str(j.pid))
				walive += 1
			else: 
				logger.debug( "   dead")
				wdead += 1
				#this will kill the controller, leaving the children pipes wanting more (you will get sigpipe errors)
				#this is pretty harsh and shouldn't probably be done in production
				#TODO
				#sys.exit(1)
		logger.info( "%s alive; %s dead" % (walive, wdead))
		updateStatus(NUMWORKERS,walive,wdead)

		list_VMs(VMs)
		time.sleep(VM_POLL_REST + 10)

		#blocks until all items in q are processed
		#safe to exit
		#should check for sigint
		#if q.qsize() == 0:
		#	for i in jobs:
		#		q.put("die")
		#	q.close()

	sys.exit(0)


	signal.signal(signal.SIGINT, sigint_handler)
	syslog.syslog('Startup - Entering main polling loop...')
	while True:

		get_VMs(VMs)
		list_VMs(VMs)
		#make sure any pcaps are killed and we are starting with a clean filesystem
		#pcap_terminate(m)
		#job_cleanup(m)

		#check for a job in the beanstalk Q
		if not beanstalk:
			error_log('Re-establishing connection to beanstalkd')
			beanstalk = beanstalkc.Connection(host=BSHOST, port=BSPORT)
			beanstalk.watch(BSMSBOXQ)
			beanstalk.use(BSMSBOXQ)
			beanstalk.ignore('default')

		#we want to reserve, not peak_ready because if we can't process, we want to release with a delay later
		beanstalkjob = beanstalk.reserve()

		#if there was a job and we got it then queue up analysis
		if beanstalkjob:
			try:
				job = eval(beanstalkjob.body)
			except:
				error_log('ERROR: could not eval job - invalid job')
				beanstalkjob.delete()
				return False

			#is there a VM compatible with this sample that is ready to be used?
			m = findCompatibleVM(job,VMs,vml)
			if m is not None:
				logger.info( "yay using VM " + str(m))
				#process sample

				sys.exit(0)

				#delete from queue if successfull
				#beanstalkjob.delete()
			else:
				#no VM found, put it back in the queue (nobody will process for 60 seconds
				beanstalkjob.release(delay=60)
				logger.info( "requeuing job requiring a target version " + job['target'])


#		
#		#break ot of the loop and exit if the assignments are clear and the terminate flag is set
		if flagTerminate and len(assignments)==0:
			syslog.syslog('All assigned jobs are completed (EXITING)...')
			break
		#put a pause in the polling cycle...set to 0 for no pause
		time.sleep(VM_POLL_REST)
		sys.exit(0)
	syslog.syslog('Shutdown - Leaving main polling loop...')
	return 0

if __name__ == '__main__':
	main()
