import zipfile, sys

if len(sys.argv) != 2:
   sys.exit("you must provide a single file name, a file to test")

def testAndroid( file ):
   isAndroid = False
   if zipfile.is_zipfile( file ):
      hasClasses = False
      hasManifest = False

      zFile = zipfile.ZipFile(sys.argv[1], "r")

      for name in zFile.namelist():
          #print name, "\n"
          if name.lower() == "classes.dex":
            hasClasses = True
          if name.lower() == "androidmanifest.xml":
            hasManifest = True
          if hasManifest and hasClasses:
            isAndroid = True
            break

      #do something if it's "almost an app?" 
      #ie taking advantage of lenience in the loader

      #for info in zFile.infolist():
      #    print info.filename, info.date_time, info.file_size
   return isAndroid 

#def testIOS ( file ):

#def testWinMobile ( file ):

#def testBB ( file ):

#print sys.argv[1]
if testAndroid(sys.argv[1]):
      print "True"
else:
      print "False"
