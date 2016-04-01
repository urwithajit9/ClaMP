#!/usr/bin/python
#Duplicate file removal script 
#This work for file have different name but same MD5 hash
#Assumption: It have been assume that MD5 is unique for each file i.e
#same MD5 comes from same file (may be different name)
#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015
#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness

#Input: 1. Path for source directory which have files
#       2. Path for output directory 
            #2.1 directory for storing copy of duplicate files
            #2.2 Directory for storing csv for file hash
            # csv file header[ID,FileName,MD5,size]
#Output: 
            #1. two CSV files (with and without duplicates) with MD5 and filesize
            #2. Moving duplicate files to give location

#Check for imported module before executating
import csv
import os
import hashlib
import shutil

class duplicateFiles():
    #Class object required input path for source directory
    # output path for keeping the duplicates files
    #output path for csv
    def __init__(self,i_path,o_path_dup_files,o_path_csv):
        self.source = i_path
        self.destin = o_path_dup_files
        self.output = o_path_csv

    def md5sum(self,filepath):
        md5 = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
                md5.update(chunk)
        return md5.hexdigest()
    
    def write_csv_header(self,filepath):
        header=["ID","fileName","MD5Hash","fileSize"]
        csv_file= open(filepath,"wa")
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(header)
        csv_file.close()

    def write_csv_data(self,filepath,data):
        csv_file= open(filepath,"a")
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(data)
        csv_file.close()

    def get_file_size(self,filepath):
        file_info = os.stat(filepath)
        return file_info.st_size

    def get_hash_file_dic(self,filepath):
        """
        This file with take csv file as input
        and will return a python dict hash:[totalfize,filenames..]
        """
        result = {}
        csv_file= open(filepath,"r")
        reader = csv.DictReader(csv_file, delimiter=',')
        for line in reader:
            if line["MD5Hash"] not in result:
                result[line["MD5Hash"]] = [1,line["fileName"]]
            else:
                result[line["MD5Hash"]][0] += 1
                result[line["MD5Hash"]].append(line["fileName"])
        return result

    def get_duplicate_files(self,hash_file_dic):
        """
        This function will take the hash:[dupfilenum,duplicate files...]
        as input and will check the dupfilenum > 1 and will give all the file
        name as list except one file.
        """
        result = [ filename for filelist in hash_file_dic.values() for filename in  filelist[2:] if filelist[0] > 1 ]
        return result
    def move_copy_of_duplicates(self,dupfiles):
        """
        This will take file names of extra copy of duplicate files
        and will move those files to the duplicate files folder given by user
        """
        for f in dupfiles:
            src = self.source + f
            try:
                shutil.move(src, self.destin)                
            except IOError :
                print "Error in moving file", src

    def write_csv_file(self,filename):
        ID = 1
        for file in os.listdir(self.source):
            filepath = self.source + file
            data=[ID,file,self.md5sum(filepath),self.get_file_size(filepath)]
            self.write_csv_data(self.output + filename,data)
            ID +=1
            print "Data written for file",file
        


def main():

    source= raw_input("Give path for Source files:(Ends with /)")
    duplicates= raw_input("Give directory path to move duplicate files.(Ends with /)")
    output= raw_input("Give path to keep output csv.(Ends with /)")
    
    filename = raw_input("Give file name for csv file. Ex. output.csv")
    md5withoutdup = raw_input("Give file name for md5 without duplicate smaples. Ex. update_output.csv")

    duplicate= duplicateFiles(source,duplicates,output)

    duplicate.write_csv_header(duplicate.output + filename)
    duplicate.write_csv_file(filename)

    hash_and_files = duplicate.get_hash_file_dic(duplicate.output + filename)
    dupfiles = duplicate.get_duplicate_files(hash_and_files)
    duplicate.move_copy_of_duplicates(dupfiles)

    duplicate.write_csv_header(duplicate.output + md5withoutdup)
    duplicate.write_csv_file(md5withoutdup)

if __name__ == '__main__':
    main()
