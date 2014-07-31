import MySQLdb
import sys
import logging

#Read and execute global config
sys.path.append('../config')
from config import *

DBCON = None

#logger = logging.getLogger("root").getChild("msdb")
#module_logger = logging.getLogger("root")
logger = logging.getLogger(__name__)

def doConnect():
	try:   
		DBCON = MySQLdb.connect(HOST,USER,PASS,DBNAME);
	except MySQLdb.Error, e:
		logger.error("Error %d: %s" % (e.args[0],e.args[1]))
		sys.exit(1)
        return DBCON

def doClose():
        if DBCON:
                DBCON.close()

def findSubmissionToUpdate(sha256hash):
	DBCON = doConnect()
	try:
		cur = DBCON.cursor()
		stmt = "select id from submissions where retrieval_key ='%s' and state='websubmit'" % (sha256hash)
		logger.debug(stmt)
		cur.execute(stmt)

		row = cur.fetchone()
		if row is not None:
			ret = str(row[0])
		else:
			ret = None
		ret = str(row[0])
	except MySQLdb.Error, e:
		logger.error( "Error %d: %s" % (e.args[0],e.args[1]))
		sys.exit(1)

	doClose()	

	return ret 


def findSample(sha256hash):
	DBCON = doConnect()
	try:
		cur = DBCON.cursor()
		stmt = "select id from malware where sha256='%s'" % (sha256hash)
		logger.debug(stmt)
		cur.execute(stmt)

		row = cur.fetchone()
		if row is not None:
			ret = str(row[0])
		else:
			ret = None
	except MySQLdb.Error, e:
		logger.error("Error %d: %s" % (e.args[0],e.args[1]))
		sys.exit(1)

	doClose()	

	return ret 

def getExistingPath(id):

	DBCON = doConnect()
	try:
		cur = DBCON.cursor()
		stmt = "select stored_path from malware where id='%s'" % (id)
		logger.debug(stmt)
		cur.execute(stmt)

		row = cur.fetchone()
		if row is not None:
			ret = str(row[0])
		else:
			ret = None
		
		
	except MySQLdb.Error, e:
		logger.error("Error %d: %s" % (e.args[0],e.args[1]))
		sys.exit(1)

	doClose()	

	return ret 

def updateStartRun(uuid,image_used,start_time,permissions_filename,version):
	stmt = "update submissions set image_used='%s',start_time='%s',permissions_filename='%s',version='%s' where retrieval_key='%s' and state = 'not done'" % (image_used,start_time,permissions_filename,version,uuid)
        DBCON = doConnect()
        try:   
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
                DBCON.commit()

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
                DBCON.rollback()
                sys.exit(1)

        doClose()

	
def updateFinishRun(uuid,complete_time,results_file):
	stmt = "update submissions set complete_time='%s',state='DONE',result='%s' where retrieval_key='%s' and state = 'not done'" % (complete_time,results_file,uuid)
        DBCON = doConnect()
        try:   
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
                DBCON.commit()

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
                DBCON.rollback()
                sys.exit(1)

        doClose()


def updateSample(thepath,thehash):
        DBCON = doConnect()
        try:   
                stmt = "update malware set stored_path='%s' where sha256='%s'" % (thepath,thehash)
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
		DBCON.commit()

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
	 	DBCON.rollback()
                sys.exit(1)

        doClose()

def updateSubmission(retrieval_key,state,result,submit_time,submit_ip,theid,sdktarget,runtime):
        DBCON = doConnect()
        try:   
                stmt = "update submissions set retrieval_key='%s', state='%s',submit_time='%s',sdktarget='%s',runtime='%s' where state='%s' and id='%s'" % (retrieval_key,state,submit_time,sdktarget,runtime,"websubmit",theid)
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
		DBCON.commit()

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
	 	DBCON.rollback()
                sys.exit(1)

        doClose()

def insertSample(stored_path,md5,sha1,sha256,size):
        DBCON = doConnect()
        try:   
                stmt = "insert into malware (stored_path,md5,sha1,sha256,size) values ('%s','%s','%s','%s','%s')" % (stored_path,md5,sha1,sha256,size)
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
		DBCON.commit()

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
	 	DBCON.rollback()
                sys.exit(1)

        try:   
                stmt = "select LAST_INSERT_ID()"
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
		row = cur.fetchone()
		if row is not None:
			ret = str(row[0])
		else:
			ret = None
		ret = int(row[0])

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
	 	DBCON.rollback()
                sys.exit(1)

        doClose()
 
	return ret

def insertSubmission(submitted_filename,retrieval_key,state,result,submit_time,submit_ip,malware_id,sdktarget,runtime):
        DBCON = doConnect()
        try:   
                stmt = "insert into submissions (submitted_filename,retrieval_key,state,result,submit_time,submit_ip,malware_id,sdktarget,runtime) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (submitted_filename,retrieval_key,state,result,submit_time,submit_ip,malware_id,sdktarget,runtime)
                logger.debug(stmt)
                cur = DBCON.cursor()
                cur.execute(stmt)
		DBCON.commit()

        except MySQLdb.Error, e:
                logger.error("Error %d: %s" % (e.args[0],e.args[1]))
	 	DBCON.rollback()
                sys.exit(1)

        doClose()

