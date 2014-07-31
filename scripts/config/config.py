
#beanstalk information
BSHOST             = 'localhost'
BSPORT             = 11300
BSMSBOXQ           = 'beanstalkqueueforanalaysis'
BSPCAPANALYZERQ    = 'beanstalkqueueforpostpcapprocessing'
#number of seconds to delay a re-inserted sample (so 1 hour)
BSDELAY            = 60 * 60

#malware is stored here
MALWARESTORAGEBASE = '/path/to/malware'
MALWAREJOBSBASE    = '/path/to/jobs'
VMSUBNET           = '192.168.1.0'
VMBASEDIR          = '/path/to/AVDs'
VMNICINDEX         = 1
SETUP_TIME_ALLOCATION = 10.0
VM_POLL_REST       = .5
HOST               = "localhost"
USER               = "ausername"
PASS               = "apassword"
DBNAME             = "adatabase"
MINSDKVER          = 4
MAXSDKVER          = 8
LOGFILE            = "master.log"
LOGFORMAT          ='%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
LOGDATEFORMAT      ='%Y-%m-%d %H:%M:%S'
#version is a increasing _integer_
MSVERSION          = 2
SDKPATH            = "/path/to/android-sdk-linux/tools"
ADBPATH            = "/path/to/android-sdk-linux/platform-tools"
