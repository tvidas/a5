#!/usr/bin/env python
import os
import zipfile, sys
import xml.dom.minidom
from lxml import etree
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from android_test import testAndroid

def addElement(parent, name, value):
   e = etree.Element(name)
   e.text=value
   parent.append(e)


def makefeeder(filein,fileout):
      root=etree.Element("root")

      app = apk.APK(filein)
      addElement(root,'sdkmin',app.get_min_sdk_version());
      addElement(root,'sdktarget',app.get_target_sdk_version());

      #print "****************the .apk contents are************"

      #for afile in app.get_files():
       #print afile


      #print "**************************************************"
      #print "the sdk version and permissions needed are"
      #print ""


      for areceiver in app.get_receivers():
       #print areceiver
       addElement(root,'receiver',areceiver)

      for act in app.get_elements("activity","android:name"):
       #print act
       addElement(root,'activity',act)

      for action in app.get_elements("action","android:name"):
       #print action
       addElement(root,'action',action)

      dx = analysis.VMAnalysis(dvm.DalvikVMFormat(app.get_dex()))
      for perm in dx.get_permissions([]):
       #print perm
       addElement(root,'rint',perm)

      for perm in app.get_permissions():
       #print perm
       addElement(root,'permission',perm)

      addElement(root,'package',app.get_package())

      feed=open(fileout,'w')
      s=etree.tostring(root,pretty_print=True)
      feed.write(s)
      feed.close()
      #print s
