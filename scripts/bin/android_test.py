import zipfile, sys


def testAndroid( file ):
   isAndroid = False
   if zipfile.is_zipfile( file ):
      hasClasses = False
      hasManifest = False

      zFile = zipfile.ZipFile(file, "r")

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
      #   print info.filename, info.date_time, info.file_size
   return isAndroid 

