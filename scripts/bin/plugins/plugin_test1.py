#filenames for plugins must start with the string "plugin_" and end in ".py"

#plugin's always return a tuple (pluginName,listOfCountermeasures,listOfComments)
#where the first value is a string and the second two are each a python List

#pluginName is a required variable for plugins
#this is simply a name for the plugin that is used in logging and stdout

pluginName = "test plugin 1"

#enable is a required variable for plugins
#if true, the plugin will be used, if false it will not

enable = True

#type is a required variable for plugins
#type is simply a string that is used to group plugins by category, often this doesn't matter

type = "test"

#logger is optional, if the plugin requests a logger like this, logging entries will end up in the shared log
#import logging
#logger = logging.getLogger(__name__)


#PluginClass is a required class for plugins
#this defines what the plugin will do, by default the plugin must have a run method that 
#accepts file strings to the associate pcap and apk files (however, these may be "None", so test for this
#if this is important in the plugin

class PluginClass:
    def run(self,pcap,apk):
        dummyrule = 'alert tcp any any -> any any (msg:"dummy test rule"; content:"AAAAAAAAAA";)'
        dummycomment = "test plugin 1 is running"
	
        ruleList = list()
        commentList = list()
  
        ruleList.append(dummyrule)
        commentList.append(dummycomment)

        return (pluginName, ruleList, commentList)

