import sys
import libIntent
import time

#this is designed to be used on a local machine with an instance of the
#emulator running

#it will test certain libIntent and adbconsole methods by speaking
#directly to the adb port

#sleeptime, so you can observe successes visually in the emulator
n = 1

li = libIntent.libIntent("localhost",5554)

time.sleep(n)
li.sendSMStoDevice()

time.sleep(n)
li.setBatteryLevel()

#li.unplugPower()
li.sendCall()

time.sleep(n)
number = li.sendCall()

time.sleep(n)
li.endCall(number)

time.sleep(n)
li.endAllCalls()

print li.getVoiceState()
print li.getDataState()
