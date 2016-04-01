#!/usr/bin/python

# Moving wrong labeled samples and Report not presents: Benign samples

#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015
#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness


#On given critera (Positive == 0) it will move all files which have
# (Positive >0) to a different location path/notbenign

#It will also move the file for which VirusTotal don't have a report
# for this purpose we will check (Total == "" ) and will move such file to 
# path/noreport

#input: path for csv file with  neccsary columns "filename" ,"MD5hash","Total","Positive"
        #path of source directory

#output: 1 csv file with VirusTotal report with header such as Filename,MD5hash,Total and Positive
        #2 moving files without VT report to path/noreport
        #3 moving files with (Positive > 0 ) to path/notbenign

#Check for imported module before executating

import os,shutil,csv

class wrong_label():
    
    def __init__(self,samplespath,VTreport_csv):
        self.source = VTreport_csv
        self.samples = samplespath

    @staticmethod
    def get_rootdir(path):
        tmp = path.split("/")
        return "/".join(tmp[0:-1]) + "/"

    @staticmethod
    def create_subdir(path):
        directory = wrong_label.get_rootdir(path)
        directory_noreport = directory + "noreport/"
        directory_notbenign = directory + "notbenign/"
        if not os.path.exists(directory_noreport ):
            os.makedirs(directory_noreport)
        if not os.path.exists(directory_notbenign ):
            os.makedirs(directory_notbenign)
    def read_csv_noreport(self):
        """
        Read csv file and return list of MD5 hashes
        """
        result=[]    
        csv_file= open(self.source,"r")
        reader = csv.DictReader(csv_file, delimiter=',')
        for line in reader:
            if line["Total"] == "":                
                result.append(line["MD5hash"])
        csv_file.close()
        return result
    def read_csv_notbenign(self):
        """
        Read csv file and return list of MD5 hashes
        """
        result=[]      
        csv_file= open(self.source,"r")
        reader = csv.DictReader(csv_file, delimiter=',')
        for line in reader:
            if line["Total"] != "":                
                if int(line["Positive"]) > 0:
                    result.append(line["MD5hash"])
        csv_file.close()
        return result
    def read_files_for_hash(self,filepath,hashes):
        """
        Read csv file and return list of MD5 hashes
        """
        result=[]      
        csv_file= open(filepath,"r")
        reader = csv.DictReader(csv_file, delimiter=',')
        for line in reader:
            if line["MD5Hash"] in hashes:
                result.append(line["fileName"])      
        csv_file.close()
        return result
    #def mov_noreport_files(self):
        #self.create_subdir(self.source)
    def mov_files(self,filelist,subdir):
        """
        This will take file names of extra copy of duplicate files
        and will move those files to the duplicate files folder given by user
        """
        self.create_subdir(self.source)
        dst = wrong_label.get_rootdir(self.source) + subdir
        for f in filelist:
            src = self.samples + f            
            try:
                #print src,dst
                shutil.move(src,dst )                
            except IOError :
                print "Error in moving file", src

def main():
    source = raw_input("Enter path of Virus Total report of benign samples. >>>")
    samplespath = raw_input("Enter the path for the benign samples. >>>")
    # Change filepath according to your set-up
    filepath= "/home/user/ClaMP/md5_after_dup.csv"


    WR = wrong_label(samplespath,source)


    noreportfiles = WR.read_files_for_hash(filepath,WR.read_csv_noreport())
    notbenignfiles = WR.read_files_for_hash(filepath,WR.read_csv_notbenign())

    WR.mov_files(noreportfiles,"noreport/")
    WR.mov_files(notbenignfiles,"notbenign/")
    print len(noreportfiles)
    print len(notbenignfiles)
    


if __name__ == "__main__":
    main()

