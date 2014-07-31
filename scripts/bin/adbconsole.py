import sys
import telnetlib
import logging

logger = logging.getLogger(__name__)

class adbConsole:

  def __init__(self, host="localhost",port=5554):
    self.HOST = host
    self.PORT = port
    self.tn = telnetlib.Telnet(self.HOST,self.PORT)
 
    #read all the adb stuff
    self.tn.read_until("OK")

  def __del__(self):
    self.tn.close()

  def close(self):
    self.tn.close()

  #note the semantics of connect are that a repeated connect
  #does NOT try to connect again, so we should always connect
  def connect(self):
    self.tn.open(self.HOST,self.PORT)
 
  def send (self,string):
    self.connect()
    if not string.endswith("\n"):
      string = string + "\n"
    logger.debug("adb sending: %s" % string)
    self.tn.write(string)
    return self.isOK()


  def isOK (self):
    (idx,match,text) = self.tn.expect(["OK","KO"],30) # 30 second timeout; should really be instant
    if idx == 0:
      #logger.debug("text:%s" % text)
      text2 = self.tn.read_until("OK")
      logger.debug("adb OK: %s" % text2)
      return text2;
    elif idx == 1:
      text2 = self.tn.read_until("KO")
      logger.debug("adb KO: %s" % text2)
      raise Exception("adb", "not OK")
    else:
      logger.error("text" + text)
      raise Exception("adb", "unk err")
    


