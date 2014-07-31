import sys
import adbconsole
import random
import string
import re 
import logging

#     this is almost entirely emulator-specific
#     new methods need to be created for devices

#Read and execute global config
sys.path.append('../config')
from config import *

#TODO log actions so we can look for numbers in the network stream

logger = logging.getLogger(__name__)

class libIntent:


  def _randomText(self,len=15):
    return "".join( [random.choice(string.letters[:26]) for i in xrange(len)] )
  def _randomNumber(self):
    return str(random.randint(1000000000,9999999999))

  def __init__(self,host="localhost",port="5554"):
    self.HOST = host
    self.PORT = port
    self.adbc = adbconsole.adbConsole(host,port)

  def __del__(self):
    self.adbc.close()

  #this is just a big switch to handle each intent
  #if you don't care about the content of the intent
  #you can just call this for each "receivable Intents"
  def handleRIntent(self,rint):
    if rint.endswith("SEND_SMS"):
      logger.info("send sms from device")
#    elif rint.endswith("READ_PHONE_STATE"):
#       self.setNet('utms')
    elif rint.endswith("RECEIVE_SMS"):
      self.sendSMStoDevice()
    else:
      logger.info( "unhandled intent: %s" % rint)

  #this is just a big switch to handle each intent
  #if you don't care about the content of the intent
  #you can just call this for each "android action"
  def handleAction(self,action):
    if action.endswith("SEND_SMS"):
      logger.info( "send sms from device")
    elif action.endswith("SMS_RECEIVED"):
      self.sendSMStoDevice()
    else:
      logger.info( "unhandled action: %s" % action )

  #this is just a big switch to handle each intent
  #if you don't care about the content of the intent
  #you can just call this for each "android permission"
  def handlePermission(self,perm):
    if perm.endswith("SEND_SMS"):
       logger.info( "")
#    elif perm.endswith("READ_PHONE_STATE"):
#       self.setNet('utms')
#    elif perm.endswith("ACCESS_NETWORK_STATE"):
#       self.setNet('utms')
    elif perm.endswith("RECEIVE_SMS"):
      self.sendSMStoDevice()
    else:
      logger.info( "unhandled perm: %s" % perm )

  #telnet localhost 5554
  #sms send 4125557777 Some sms message here
  def sendSMStoDevice(self,number=None,msg=None):
    if number == None:
      number = self._randomNumber()
      #number = str(random.randint(1000000000,9999999999))
    if msg == None:
      msg = self._randomText(40)
    self.adbc.send("sms send %s %s" % (number, msg))

  #list types with "event types"
  #list codes with "event codes <type>"
  def sendHWEventtoDevice(self,atype=None,acode=None,avalue=None):
    #TODO add plausible data for Nones
    self.adbc.sent("event send %s:%s:%s" % ( atype, acode, avalue))

  def sendHWTextEventtoDevice(self,text=None):
    if text == None:
      text = self._randomText()
    self.adbc.send("event text %s" % ( text ))

  def plugPower(self):
    self.adbc.send("power status charging")
    self.adbc.send("power ac on")

  def unplugPower(self):
    #TODO set threaded timer such that it loses 1 percent every X min
    self.adbc.send("power status discharging")
    self.adbc.send("power ac off")

  def setBatteryLevel(self,percent=None):
    if percent == None:
      percent = str(random.randint(1,100))
    self.adbc.send("power capacity %s" % (percent))

  def setNetDelay(self,netType=None):
    netTypes = ['gprs','edge','umts','none']
    if netType == None:
      netType = choice(netTypes)
    self.adbc.send("network delay %s" % (netTypes))
    
  def setNetSpeed(self,netSpeed=None):
    netSpeeds = ['gsm','hscsd','gprs','edge','umts','hsdpa','full']
    if netSpeed == None:
      netType = choice(netTypes)
    self.adbc.send("network speed %s" % (netTypes))

  def setNet(self,netType=None):
    netTypes = ['gprs','edge','umts','none']
    if netType == None:
      netType = choice(netTypes)
    self.setNetDelay(netType)
    self.setNetSpeed(netType)

  def setGeo(self,lon=None,lat=None, alt=None):
    if lon == None:
      lon = random.randint(-180,180)
    if lat == None:
      lat = random.randint(-90,90)
    if alt == None:
      self.adbc.send("gsm fix %s %s" % (lon,lat))
    else:
      self.adbc.send("gsm fix %s %s %s" % (lon,lat,alt))

  def setNmea(self,nmea):
    """sends a NMEA string directly to the device; requires nmea string"""
    self.adbc.send("gsm nmea %s" % (nmea))

  def setDataState(self,stateType=None):
    stateTypes = ['unregistered','home','roaming','searching','denied','off','on']
    if stateType == None:
      stateType = choice(netTypes)
    self.adbc.send("gsm data %s" % (stateType))

  def setVoiceState(self,stateType=None):
    stateTypes = ['unregistered','home','roaming','searching','denied','off','on']
    if stateType == None:
      stateType = choice(netTypes)
    self.adbc.send("gsm voice %s" % (stateType))

  def getDataState(self):
    stateTypes = ['unregistered','home','roaming','searching','denied','off','on']
    states = self.adbc.send("gsm status" )
    for line in states.split('\n'):
      if "data" in line:
        return line.rsplit(' ', 1)[-1] 

  def getVoiceState(self):
    stateTypes = ['unregistered','home','roaming','searching','denied','off','on']
    states = self.adbc.send("gsm status" )
    for line in states.split('\n'):
      if "voice" in line:
        return line.rsplit(' ', 1)[-1] 

  def sendCall(self,number=None):
    """send a call to a device, if omitted number is randomly selected and returned"""
    if number == None:
      number = self._randomNumber()
    self.adbc.send("gsm call %s" % (number))
    return number

  def acceptCall(self,number):
    """accept a call; requires a specific number"""
    self.adbc.send("gsm accept %s" % (number))

  def holdCall(self,number):
    """ place an outbound call on hold"""
    self.adbc.send("gsm hold")
  
  def endCall(self,number):
    """end a call to a specific number"""
    self.adbc.send("gsm cancel %s" % (number))

  #gsm list
  #outbound to  5407282290 : held
  #inbound from 4443332222 : incoming
  def endAllCalls(self):
    """determine alls current calls and ends them"""
    callList = self.adbc.send("gsm list")
    #r = re.compile(r'\d{3}[-\.\s]\d{3}[-\.\s]\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]\d{4}|\d{3}[-\.\s]\d{4}')
    r = re.compile(r'\d+')
    numbers = r.findall(callList)
    for n in numbers:
      self.endCall(n)
    

#def sendSMSfromDevice():
#./adb shell am start -a android.intent.action.SENDTO -d sms:4125558888 --es sms_body "hi there" --ez exit_on_sent true
#./adb shell input keyevent 22
#./adb shell input keyevent 66



#TODO plug/unplug power, etc
#http://developer.android.com/tools/devices/emulator.html#sms


#am start -a android.intent.action.CALL -d tel://000-0000
 
#am start -a android.intent.action.SEND -d "some message" -t text/plain
 
#am start -a android.intent.action.VIEW -d geo:0,0?q=Tokyo
