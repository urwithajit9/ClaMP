"""
Author: Ajit Kumar
Date: 12 April 2015
Again Tested and sanitize on 01-04-2016 (Ubuntu 14.4 LTS)
email: urwithajit9@gmail.com

## This program will itrate through all files of a given path and
## extract each section data for given file and will 
## calculate entropy for each section
## 

### Input: Path for files (Portable excutable)
### Output: csv file with heading ["filename","filesize","entropy"]
"""
#import required module 

import pefile,csv,os,math


#Give path of samples Below are example 

# Note : Please change test and output_file according to your environment

test= "/home/user/ClaMP/test-data/"

output_file = "/home/user/ClaMP/raw-samples-metadata/output.csv"

def get_file_bytes_size(filePath):
	f = open(filePath, "rb")
	byteArr = map(ord, f.read())
	f.close()
	fileSize = len(byteArr)
	return byteArr,fileSize

def cal_byteFrequency(byteArr,fileSize):
	freqList = []
	for b in range(256):
		ctr = 0
		for byte in byteArr:
			if byte == b:
				ctr += 1
		freqList.append(float(ctr) / fileSize)
	return freqList

def get_size_and_entropy(filePath):
	byteArr, fileSize = get_file_bytes_size(filePath)
	freqList = cal_byteFrequency(byteArr,fileSize)
	 # Shannon entropy
	ent = 0.0
	for freq in freqList:
		if freq > 0:
			ent +=  - freq * math.log(freq, 2)

			#ent = -ent
	return fileSize,ent




#open csv file for writing data

csv_file= open(output_file,"wa")	

writer = csv.writer(csv_file, delimiter=',')

writer.writerow(["filename","filesize","entropy"])



for file in os.listdir(test):	
	data=[]
	try:
		pe = pefile.PE(test + file)
	except Exception, e:
		print "error while loading ..."
	else:
		filesize, entropy = get_size_and_entropy(test + file)
		data= [file,filesize,entropy]	
		print "writing for {}".format(file)	
        writer.writerow(data)

print "All Entropy calculated and written to file.", output_file

csv_file.close()
    
		
		

