#!/usr/bin/python
#Virus Total Report fetching:Benign samples

#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015
#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness


#This script will take a csv file with MD5 hash as input 
#and it will read all MD5 and will fetch the VirusTotal report
#on each MD5 and after receiveing and parsing the report
# will write them to a CSV file path/report.csv

# The CSV file header will have fields as
#[ID,fileName,MD5hash,Total,Positive,type-TrendMicro,type-F-secure,Scan-Date]


#input: path for csv file with one column have MD5 hash prfer headername as "MD5hash"

#output: csv file with VirusTotal report with header such as Total and Positive
        
#Note: You need to register to VirusTotal and get API Key to use this script. Give your key
#value to self.mykey= ""
#Check for imported module before executating

import csv,urllib, urllib2,simplejson,time

class benign_label():
    
    def __init__(self,source,output):
        self.source = source
        self.output = output
        self.url = "https://www.virustotal.com/vtapi/v2/file/report"
        self.mykey = "give your own virus total key"

    def read_csv(self):
        result={}
        id={}
        csv_file= open(self.source,"r")
        reader = csv.DictReader(csv_file, delimiter=',')
        for line in reader:
            if line["MD5Hash"] not in result:
                result[line["MD5Hash"]] = line["fileName"]
                id[line["MD5Hash"]] = line["ID"]
        return result,id
        
    def get_rootdir(self):
        tmp = self.source.split("/")
        return "/".join(tmp[0:-1]) + "/"

    def write_csv_header(self):
        filepath = self.get_rootdir() + self.output
        header=["ID","fileName","MD5Hash","Total","Positive","Type-TrendMicro","Type-F-secure","Scan-Date"]
        csv_file= open(filepath,"wa")
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(header)
        csv_file.close()

    def write_csv_data(self,data):
        filepath = self.get_rootdir() + self.output
        csv_file= open(filepath,"a")
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(data)
        csv_file.close()

    def request_report(self,md5hash):        
        parameters ={"resource":md5hash,"apikey":self.mykey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url, data)
        response = urllib2.urlopen(req)
        result= response.read() 
        return result

    def parse_report(self,VTreport,hashfileName,hashID): 
        """
        Take Virus Total report and hashfile, hashID dict as intput and
        return the list of data item         
        """
        #Improve code for handling the empty report
        result_json = simplejson.loads(VTreport)
        md5 = result_json.get("md5")
        id = hashID[md5]
        filename= hashfileName[md5]
        total=result_json.get("total")
        positives= result_json.get("positives")
        trendMicro = result_json.get("scans", {}).get("TrendMicro", {}).get("result")
        f_secure= result_json.get("scans", {}).get("F-Secure", {}).get("result")
        scan_date = result_json.get("scan_date")

        return [id,filename,md5,total,positives,trendMicro,f_secure,scan_date]


def main():    
    source_path= raw_input("Enter the csv file path with MD5 hashes.(Absoulte path end with .csv) >>  ")
    output_file= raw_input("Give file name of output file. >>")

    BL = benign_label(source_path,output_file)

    hashfilename,hashID = BL.read_csv()
    BL.write_csv_header()

    for md5hash in hashfilename.keys():
        result = BL.request_report(md5hash)
        if result:
            BL.write_csv_data(BL.parse_report(result,hashfilename,hashID))
            print "Report fetch and written for MD5 :  ",md5hash
        else:
            #can write hash MD5 to a txt file
            print "No report found for ",md5hash
        time.sleep(18)
if __name__ == '__main__':
    main()



