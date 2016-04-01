#!/usr/bin/python
#Get file info of any file

#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015
#Thanx to Ero Carrera for creating pefile. https://github.com/erocarrera/pefile

#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness

#input: path for Directory

#output: all file info in given directory such FileVersion, ProductVersion etc.
        
#import required python modules

import pefile
import os


# Change value of source according to your setup

source = "/home/user/ClaMP/test-data/"



def get_fileinfo(pe):
	result=[]
	try:
		FileVersion    = pe.FileInfo[0].StringTable[0].entries['FileVersion']
		ProductVersion = pe.FileInfo[0].StringTable[0].entries['ProductVersion']
		ProductName = 	 pe.FileInfo[0].StringTable[0].entries['ProductName']
		CompanyName = pe.FileInfo[0].StringTable[0].entries['CompanyName']
	#getting Lower and 
		FileVersionLS    = pe.VS_FIXEDFILEINFO.FileVersionLS
		FileVersionMS    = pe.VS_FIXEDFILEINFO.FileVersionMS
		ProductVersionLS = pe.VS_FIXEDFILEINFO.ProductVersionLS
		ProductVersionMS = pe.VS_FIXEDFILEINFO.ProductVersionMS
	except Exception, e:
		result=["error"]
		#print "{} while opening {}".format(e,filepath)
	else:
	#shifting byte
		FileVersion = (FileVersionMS >> 16, FileVersionMS & 0xFFFF, FileVersionLS >> 16, FileVersionLS & 0xFFFF)
		ProductVersion = (ProductVersionMS >> 16, ProductVersionMS & 0xFFFF, ProductVersionLS >> 16, ProductVersionLS & 0xFFFF)
		result = [FileVersion,ProductVersion,ProductName,CompanyName]
	return result




for file in os.listdir(source):
	filepath = source+file
	try:
		pe = pefile.PE(filepath)
	except Exception, e:
		print "{} while opening {}".format(e,filepath)
	else:
		print get_fileinfo(pe)
		"""
		if data[0] == "error" or data == []:
			print 0
		else:
			print 1
		"""

"""
#Sample Output
print 'File version:    %s.%s.%s.%s' % FileVersion 
print 'Product version: %s.%s.%s.%s' % ProductVersion
print 'ProductName: %s' % ProductName
print 'CompanyName : %s' %CompanyName

{
u'LegalCopyright': u'',
u'FileVersion': u'', 
u'CompanyName': u'Media Finder',
u'Comments': u'This installation was built with Inno Setup.',
u'ProductName': u'Bootstrap',
u'ProductVersion': u'1.0',
u'FileDescription': u'Bootstrap Setup'
}

"""
