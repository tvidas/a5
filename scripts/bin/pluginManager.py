import sys
import os.path
from pkgutil import walk_packages
import md5
import imp
import traceback
import logging

#Read and execute global config
sys.path.append('../config')
from config import *

logger = logging.getLogger(__name__)


#this plugin handling method was inspired by 
#http://stackoverflow.com/questions/16597242/best-way-to-dynamically-load-plugins-in-a-python-library

#POSTPROCESSMODULEDIR = "/some/path/to/plugins"

class pluginManager:


  #structures = __import__('postprocess.notcompatible',fromlist=['unused value'])
  
  #import all
  #plugins = [ __import__('postprocess.%s.rule' % pkg, fromlist=['unused value']) for pkg in packages ]
  #objects = [ m.MyClass() for m in plugins ]
  
  def __init__(self):
    self.loaddir = POSTPROCESSMODULEDIR
    sys.path.append(self.loaddir)
    self.plugins = []
    self.thisPlugin = 0
    self.disabledCount = 0
  
  def loadPlugins(self,path=POSTPROCESSMODULEDIR,type="all"):
    "This function loads all plugins from the supplied directory"
    logger.debug( "loading from %s" % path)
    for file in os.listdir(str(path)):
      logger.debug(str(file))
      self.loadPlugin(file,type)
    logger.info("loaded %d plugins" % len(self.plugins))
    logger.info("%d plugins not loaded because they are disabled" % self.disabledCount)
  
  def loadPlugin(self,thefile,type="all"):
     "This function loads a particular plugin from a file, file must start with 'plugin_' and end in py"
     if (os.path.basename(thefile)[0:7] == "plugin_" and thefile[-3:] == ".py"):
          self.thisPlugin = __import__(".".join(thefile.split(".")[0:-1]))
          logger.debug("mported %s" % self.thisPlugin.pluginName)
          logger.debug( "plugin type is %s for %s" % (self.thisPlugin.type,self.thisPlugin.pluginName))
          if (self.thisPlugin.enable == True and (self.thisPlugin.type == type or type == "all")):
              self.plugins.append(self.thisPlugin)
          else:
              self.disabledCount += 1
              logger.debug("not loading %s because it's disabled." % self.thisPlugin.pluginName)
  
  def listPlugins(self):
      "This function should print the names of all loaded plugins."
      for m in self.plugins:
          logger.debug("plugin %s" % m.pluginName)
          print "loaded: %s" % m.pluginName
  
  def runPlugins(self,pcap=None,apk=None):
      "This function should execute the run method for ALL plugins."
      returnList = list()
      for m in self.plugins:
          c = m.PluginClass()
          returnList.append(c.run(pcap,apk))
      return returnList
  
  def selectPlugin(self,pluginNum):
      "This function should let us select a single plugin for the runSelectedPlugin function."
      self.thisPlugin = self.plugins[pluginNum]
  
  def runSelectedPlugin(self,pcap=None,apk=None):
      "This function should run the 'run' method for ONLY the previously selected plugin."
      if (self.thisPlugin == 0):
          raise ArgumentError("you didn't assign a plugin yet.")
      c = self.thisPlugin.PluginClass()
      return c.run(pcap,apk)

def setupLogger(name,filename):
    formatter = logging.Formatter(fmt=LOGFORMAT,datefmt=LOGDATEFORMAT)
    handler = logging.FileHandler(filename)
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger

def printDataList(pluginDataList):
  if pluginDataList is not None and len(pluginDataList) > 0:  
    for pluginData in pluginDataList:
      (name,ruleList,commentList) = pluginData
      print "====%s====" % name
      if ruleList is not None and len(ruleList) > 0:
        print "----rules----"
        for rule in ruleList:
          print "  %s" % rule
      if commentList is not None and len(commentList) > 0:
        print "----comments----"
        for comment in commentList:
          print "  %s" % comment
  else:
    print "no rules produced data"
  
  
def main():

  logger = setupLogger("root","pluginManager.log")

  pm = pluginManager() 
  #pm.loadPlugins(POSTPROCESSMODULEDIR)
  print "default is to only load test plugins"
  #pm.loadPlugins(type="test")
  pm.loadPlugins(type="all")
  pm.listPlugins()
  pluginDataList = pm.runPlugins("/path/to/notc-pruned.pcap",None)
  printDataList(pluginDataList)
  pluginDataList = pm.runPlugins("/path/to/notcompatible-cmds.pcap","/path/to/notcompatible.apk")
  printDataList(pluginDataList)

  
if __name__ == "__main__":
      main()
