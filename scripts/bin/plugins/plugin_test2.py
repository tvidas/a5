
pluginName = "test plugin 2"

enable = False 

type = "test"

class PluginClass:
    def run(self,pcap,apk):
        dummyrule = 'alert tcp any any -> any any (msg:"dummy test rule"; content:"AAAAAAAAAA";)'
        dummycomment = "test plugin 2 is running"
        
        ruleList = list()
        commentList = list()

        ruleList.append(dummyrule)
        commentList.append(dummycomment)

        return (pluginName, ruleList, commentList)


