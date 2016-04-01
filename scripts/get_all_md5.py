#!/usr/bin/python
#Calculate MD5 hash for all files in given Directory and Write them to CSV

#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015

#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness


# The CSV file header will have fields as ["fileName","MD5hash"]



#input: path for Directory in which files are stored to calculate MD5

#output: csv file filename and MD5
        
#import required python modules
import sys
import hashlib
import os
import csv

#MD5 calculation function

def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()


#change roodir and output values according to your setup

rootdir= "/home/user/ClaMP/test-data"
output= "/home/user/ClaMP/MD5_hash.csv"

count=1

csv_file = open(output,"wa")


writer = csv.writer(csv_file, delimiter=',')
writer.writerow(["fileName","MD5hash"])


for subdir,dirs,files in os.walk(rootdir):
	for file in files:
            try:
                fileHash= md5sum(rootdir + '/' + file)					
            except Exception, e:
                print ("Error while calculating MD5 for the file",file)            
            else:    
                print "Writing file number", count        		
                writer.writerow([file,fileHash])
                count += 1
	csv_file.close()
			
		
			

	

	




