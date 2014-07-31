
# python beanstalk-text.py 

#Read and execute global config
sys.path.append('../config')
from config import *


import beanstalkc
c = beanstalkc.Connection(host=BSHOST, port=BSPORT)
print ( c.put('hey!'))
job = c.reserve()
print (job.body)
print(job.delete())
