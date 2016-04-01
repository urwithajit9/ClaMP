#!/usr/bin/python
#raw featrues extraction (total 55) for ClaMP

#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015
#Thanx to Ero Carrera for creating pefile. https://github.com/erocarrera/pefile

#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness

#input: Directory path of samples
	#File path of output (csv)
	# Class label 0,1 (clean,malware)

#output: csv with all extracted features
# Note: please change so
        
#import required python modules
import os
import pefile
import csv

# Creating header

IMAGE_DOS_HEADER = ["e_magic","e_cblp","e_cp", "e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp",\
 "e_csum","e_ip","e_cs","e_lfarlc","e_ovno","e_res","e_oemid","e_oeminfo","e_res2","e_lfanew"]  



FILE_HEADER= ["Machine","NumberOfSections","CreationYear","PointerToSymbolTable", \
              "NumberOfSymbols","SizeOfOptionalHeader","Characteristics"]

OPTIONAL_HEADER = ["Magic","MajorLinkerVersion","MinorLinkerVersion","SizeOfCode","SizeOfInitializedData",\
"SizeOfUninitializedData","AddressOfEntryPoint",\
"BaseOfCode","BaseOfData","ImageBase","SectionAlignment","FileAlignment",\
"MajorOperatingSystemVersion","MinorOperatingSystemVersion",\
"MajorImageVersion",\
"MinorImageVersion",\
"MajorSubsystemVersion",\
"MinorSubsystemVersion",\
"SizeOfImage",\
"SizeOfHeaders",\
"CheckSum",\
"Subsystem",\
"DllCharacteristics",\
"SizeOfStackReserve",\
"SizeOfStackCommit",\
"SizeOfHeapReserve",\
"SizeOfHeapCommit",\
"LoaderFlags",\
"NumberOfRvaAndSizes"]

def file_creation_year(seconds):
    return 1970 + ((int(seconds) / 86400) / 365)   


def extract_dos_header(pe):
        IMAGE_DOS_HEADER_data = [ 0 for i in range(19)]
        try:
            IMAGE_DOS_HEADER_data = [
				pe.DOS_HEADER.e_magic,\
                                pe.DOS_HEADER.e_cblp,\
                                pe.DOS_HEADER.e_cp, \
				pe.DOS_HEADER.e_crlc,\
                                pe.DOS_HEADER.e_cparhdr,\
				pe.DOS_HEADER.e_minalloc,\
                                pe.DOS_HEADER.e_maxalloc,\
				pe.DOS_HEADER.e_ss,\
                                pe.DOS_HEADER.e_sp,\
				pe.DOS_HEADER.e_csum,\
				pe.DOS_HEADER.e_ip,\
				pe.DOS_HEADER.e_cs,\
				pe.DOS_HEADER.e_lfarlc,\
				pe.DOS_HEADER.e_ovno,\
				pe.DOS_HEADER.e_res,\
				pe.DOS_HEADER.e_oemid,\
				pe.DOS_HEADER.e_oeminfo,\
				pe.DOS_HEADER.e_res2,\
                                pe.DOS_HEADER.e_lfanew]
        except Exception, e:
            print e
        return IMAGE_DOS_HEADER_data
def extract_features(pe):
    IMAGE_DOS_HEADER_data= extract_dos_header(pe)	

    FILE_HEADER_data = [ pe.FILE_HEADER.Machine, \
                    pe.FILE_HEADER.NumberOfSections, \
                    file_creation_year(pe.FILE_HEADER.TimeDateStamp), \
                    pe.FILE_HEADER.PointerToSymbolTable,\
                    pe.FILE_HEADER.NumberOfSymbols,\
                    pe.FILE_HEADER.SizeOfOptionalHeader,\
                    pe.FILE_HEADER.Characteristics ]


    OPTIONAL_HEADER_data = [pe.OPTIONAL_HEADER.Magic,\
                pe.OPTIONAL_HEADER.MajorLinkerVersion,\
                pe.OPTIONAL_HEADER.MinorLinkerVersion,\
                pe.OPTIONAL_HEADER.SizeOfCode,\
                pe.OPTIONAL_HEADER.SizeOfInitializedData,\
                pe.OPTIONAL_HEADER.SizeOfUninitializedData,\
                pe.OPTIONAL_HEADER.AddressOfEntryPoint,\
                pe.OPTIONAL_HEADER.BaseOfCode,\
                pe.OPTIONAL_HEADER.BaseOfData,\
                pe.OPTIONAL_HEADER.ImageBase,\
                pe.OPTIONAL_HEADER.SectionAlignment,\
                pe.OPTIONAL_HEADER.FileAlignment,\
                pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,\
                pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,\
                pe.OPTIONAL_HEADER.MajorImageVersion,\
                pe.OPTIONAL_HEADER.MinorImageVersion,\
                pe.OPTIONAL_HEADER.MajorSubsystemVersion,\
                pe.OPTIONAL_HEADER.MinorSubsystemVersion,\
                pe.OPTIONAL_HEADER.SizeOfImage,\
                pe.OPTIONAL_HEADER.SizeOfHeaders,\
                pe.OPTIONAL_HEADER.CheckSum,\
                pe.OPTIONAL_HEADER.Subsystem,\
                pe.OPTIONAL_HEADER.DllCharacteristics,\
                pe.OPTIONAL_HEADER.SizeOfStackReserve,\
                pe.OPTIONAL_HEADER.SizeOfStackCommit,\
                pe.OPTIONAL_HEADER.SizeOfHeapReserve,\
                pe.OPTIONAL_HEADER.SizeOfHeapCommit,\
                pe.OPTIONAL_HEADER.LoaderFlags,\
                pe.OPTIONAL_HEADER.NumberOfRvaAndSizes]   

    return IMAGE_DOS_HEADER_data + FILE_HEADER_data + OPTIONAL_HEADER_data


# Please change rootdir, output and class_label according to your setup

rootdir = "/home/user/ClaMP/test-data/"
output= "/home/user/ClaMP/raw_features.csv"
class_label=['clean']  # Change this accroding to sample [0] or [1] can also be used

f = open(output, 'wt')
writer = csv.writer(f)
writer.writerow(IMAGE_DOS_HEADER+FILE_HEADER + OPTIONAL_HEADER + ['class'])


for subdir,dirs,files in os.walk(rootdir):
    for file in files:       
        input_file = rootdir + '/' + file
        try:
            pe =  pefile.PE(input_file)            
        except Exception, e:
            print "Exception while loading file: ", e        
        else:
            try:   
                features = extract_features(pe)                
                writer.writerow(features+ class_label)
            except Exception, e:
                print "Exception while opening and writing CSV file: ", e
                
f.close()
            
           

