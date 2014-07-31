
#pluginName is a required variable for plugins
#this is simply a name for the plugin that is used in logging and stdout

pluginName = "DNS to Host Rule"

#enable is a required variable for plugins
#if true, the plugin will be used, if false it will not

enable = True

#type is a required variable for plugins
#type is simply a string that is used to group plugins by category, often this doesn't matter

type = "generic"

#logger is optional, if the plugin requests a logger like this, logging entries will end up in the shared log
import logging
logger = logging.getLogger(__name__)


#PluginClass is a required class for plugins
#this defines what the plugin will do, by default the plugin must have a run method

class PluginClass:
    msg = "autocreated dns->host rule"

    def get_host_rule(self,domain):  
      return 'alert tcp any any -> any any (msg:"%s"; content:"Host|3A20|"; content:"%s|0D 0A|"; within:64;)' % (self.msg,domain)

    def run(self,pcap,apk):
        ruleList = list()
        commentList = list()

	if pcap is None:
          commentList.append("this plugin requires a pcap file to work")
          logger.error("plugin requires a pcap...but didn't get one")
          return (pluginName,None,commentList)


        try:
          from scapy.all import PcapReader,hexdump,ls
          import sys

          my_reader = PcapReader(pcap)
          self.process_it(my_reader,ruleList)
        except IOError:
          logger.error("Failed reading pcap")
          return (pluginName, None, None)

        return (pluginName, ruleList, commentList)
    
    def process_it(self,reader,ruleList):
      from scapy.all import ls,DNS
      cnt = 0 
      dnscnt = 0
    
      for pkt in reader:
        cnt += 1
        payload = pkt.payload
        #print payload[IP].dst
 	#these appear to be equivalent...
        #if DNS in pkt:  
        if pkt.haslayer(DNS):
          dnscnt += 1
          #<DNSQR  qname='3na3budet9.ru.\x1d.' qtype=A qclass=IN |> (None)
          #ls(payload)
          #hexdump(pkt)
          #pkt.summary()
          #pkt.show2()
          #pkt.sprintf()
          #pkt.psdump()
          #pkt.pdfdump()
          if pkt.qd.qtype == 1:
            ruleList.append(self.get_host_rule(pkt.qd.qname))
      logger.info("%d packets, %d dns" %(cnt,dnscnt))
   
 

