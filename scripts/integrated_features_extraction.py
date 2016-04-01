#!/usr/bin/python
#Integrated Featrues extraction for ClaMP

#Written by: Ajit kumar, urwithajit9@gmail.com ,25Feb2015
#Thanx to Ero Carrera for creating pefile. https://github.com/erocarrera/pefile

#No license required for any kind of reuse
#If using this script for your work, please refer this on your willingness

#input: Directory path of samples
	#File path of output (csv)
	# Class label 0,1 (clean,malware)

#output: csv with all extracted features
        
#import required python modules

#Need to install yara and pefile external python module
# Need to compile PEiD signatures as yara rules ( scripts are available online, later i will upload this too)

# Change at line 79 self.rules= yara.compile(filepath='/home/user/ClaMP/yara/peid.yara') to your comple rules



import csv,os,pefile
import yara
import math



class pe_features():

    IMAGE_DOS_HEADER = [
                        "e_cblp",\
                        "e_cp", \
                        "e_cparhdr",\
                        "e_maxalloc",\
                        "e_sp",\
                        "e_lfanew"]

    FILE_HEADER= ["NumberOfSections","CreationYear"] + [ "FH_char" + str(i) for i in range(15)]
                

    OPTIONAL_HEADER1 = [
                        "MajorLinkerVersion",\
                        "MinorLinkerVersion",\
                        "SizeOfCode",\
                        "SizeOfInitializedData",\
                        "SizeOfUninitializedData",\
                        "AddressOfEntryPoint",\
                        "BaseOfCode",\
                        "BaseOfData",\
                        "ImageBase",\
                        "SectionAlignment",\
                        "FileAlignment",\
                        "MajorOperatingSystemVersion",\
                        "MinorOperatingSystemVersion",\
                        "MajorImageVersion",\
                        "MinorImageVersion",\
                        "MajorSubsystemVersion",\
                        "MinorSubsystemVersion",\
                        "SizeOfImage",\
                        "SizeOfHeaders",\
                        "CheckSum",\
                        "Subsystem"] 
    OPTIONAL_HEADER_DLL_char = [ "OH_DLLchar" + str(i) for i in range(11)]                   
                            
    OPTIONAL_HEADER2 = [
                        "SizeOfStackReserve",\
                        "SizeOfStackCommit",\
                        "SizeOfHeapReserve",\
                        "SizeOfHeapCommit",\
                        "LoaderFlags"]  # boolean check for zero or not
    OPTIONAL_HEADER = OPTIONAL_HEADER1 + OPTIONAL_HEADER_DLL_char + OPTIONAL_HEADER2
    Derived_header = ["sus_sections","non_sus_sections", "packer","packer_type","E_text","E_data","filesize","E_file","fileinfo"]
    def __init__(self,source,output,label):
        self.source = source
        self.output = output
        self.type = label
	#Need PEiD rules compile with yara
        self.rules= yara.compile(filepath='/home/user/ClaMP/yara/peid.yara')
        

    def file_creation_year(self,seconds):
        tmp = 1970 + ((int(seconds) / 86400) / 365)
        return int(tmp in range (1980,2016)) 


    def FILE_HEADER_Char_boolean_set(self,pe):
        tmp = [pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE,\
            pe.FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM,\
            pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE,\
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO,\
            pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE,\
            pe.FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED,\
            pe.FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,\
            pe.FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP,\
            pe.FILE_HEADER.IMAGE_FILE_SYSTEM,\
            pe.FILE_HEADER.IMAGE_FILE_DLL,\
            pe.FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY,\
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI
            ]
        return [int(s) for s in tmp]

    def OPTIONAL_HEADER_DLLChar(self,pe):
        tmp = [
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_BIND,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_APPCONTAINER,\
            pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF
            ]
        return [int(s) for s in tmp]
    def Optional_header_ImageBase(self,ImageBase):
        result= 0
        if ImageBase % (64 * 1024) == 0 and ImageBase in [268435456,65536,4194304]:
            result = 1
        return result
    def Optional_header_SectionAlignment(self,SectionAlignment,FileAlignment):
        """This is boolean function and will return 0 or 1 based on condidtions
        that it SectionAlignment must be greater than or equal to FileAlignment
        """
        return int(SectionAlignment >= FileAlignment)
    def Optional_header_FileAlignment(self,SectionAlignment,FileAlignment):
        result =0
        if SectionAlignment >= 512:
            if FileAlignment % 2 == 0 and FileAlignment in range(512,65537):
                result =1
        else: 
            if FileAlignment == SectionAlignment:
                result = 1
        return result

    def Optional_header_SizeOfImage(self,SizeOfImage,SectionAlignment):
        return int(SizeOfImage % SectionAlignment == 0)

    def Optional_header_SizeOfHeaders(self,SizeOfHeaders,FileAlignment):
        return int(SizeOfHeaders % FileAlignment == 0 )


    def extract_dos_header(self,pe):
        IMAGE_DOS_HEADER_data = [ 0 for i in range(6)]
        try:
            IMAGE_DOS_HEADER_data = [
                                pe.DOS_HEADER.e_cblp,\
                                pe.DOS_HEADER.e_cp, \
                                pe.DOS_HEADER.e_cparhdr,\
                                pe.DOS_HEADER.e_maxalloc,\
                                pe.DOS_HEADER.e_sp,\
                                pe.DOS_HEADER.e_lfanew]
        except Exception, e:
            print e
        return IMAGE_DOS_HEADER_data

    def extract_file_header(self,pe):	
        FILE_HEADER_data = [ 0 for i in range(3)]
        FILE_HEADER_char =  []
        try:
            FILE_HEADER_data = [ 
                    pe.FILE_HEADER.NumberOfSections, \
                    self.file_creation_year(pe.FILE_HEADER.TimeDateStamp)]
            FILE_HEADER_char = self.FILE_HEADER_Char_boolean_set(pe)
        except Exception, e:
            print e
        return FILE_HEADER_data + FILE_HEADER_char

    def extract_optional_header(self,pe):
        OPTIONAL_HEADER_data = [ 0 for i in range(21)]
        DLL_char =[]
        OPTIONAL_HEADER_data2 = [ 0 for i in range(6)]

        try:
            OPTIONAL_HEADER_data = [
                pe.OPTIONAL_HEADER.MajorLinkerVersion,\
                pe.OPTIONAL_HEADER.MinorLinkerVersion,\
                pe.OPTIONAL_HEADER.SizeOfCode,\
                pe.OPTIONAL_HEADER.SizeOfInitializedData,\
                pe.OPTIONAL_HEADER.SizeOfUninitializedData,\
                pe.OPTIONAL_HEADER.AddressOfEntryPoint,\
                pe.OPTIONAL_HEADER.BaseOfCode,\
                pe.OPTIONAL_HEADER.BaseOfData,\
                #Check the ImageBase for the condition
                self.Optional_header_ImageBase(pe.OPTIONAL_HEADER.ImageBase),\
                # Checking for SectionAlignment condition
                self.Optional_header_SectionAlignment(pe.OPTIONAL_HEADER.SectionAlignment,pe.OPTIONAL_HEADER.FileAlignment),\
                #Checking for FileAlignment condition
                self.Optional_header_FileAlignment(pe.OPTIONAL_HEADER.SectionAlignment,pe.OPTIONAL_HEADER.FileAlignment),\
                pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,\
                pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,\
                pe.OPTIONAL_HEADER.MajorImageVersion,\
                pe.OPTIONAL_HEADER.MinorImageVersion,\
                pe.OPTIONAL_HEADER.MajorSubsystemVersion,\
                pe.OPTIONAL_HEADER.MinorSubsystemVersion,\
                #Checking size of Image
                self.Optional_header_SizeOfImage(pe.OPTIONAL_HEADER.SizeOfImage,pe.OPTIONAL_HEADER.SectionAlignment),\
                #Checking for size of headers
                self.Optional_header_SizeOfHeaders(pe.OPTIONAL_HEADER.SizeOfHeaders,pe.OPTIONAL_HEADER.FileAlignment),\
                pe.OPTIONAL_HEADER.CheckSum,\
                pe.OPTIONAL_HEADER.Subsystem]

            DLL_char = self.OPTIONAL_HEADER_DLLChar(pe)

            OPTIONAL_HEADER_data2= [                
                pe.OPTIONAL_HEADER.SizeOfStackReserve,\
                pe.OPTIONAL_HEADER.SizeOfStackCommit,\
                pe.OPTIONAL_HEADER.SizeOfHeapReserve,\
                pe.OPTIONAL_HEADER.SizeOfHeapCommit,\
                int(pe.OPTIONAL_HEADER.LoaderFlags == 0) ]
        except Exception, e:
            print e
        return OPTIONAL_HEADER_data + DLL_char + OPTIONAL_HEADER_data2

    def get_count_suspicious_sections(self,pe):
        result=[]
        tmp =[]
        benign_sections = set(['.text','.data','.rdata','.idata','.edata','.rsrc','.bss','.crt','.tls'])
        for section in pe.sections:
            tmp.append(section.Name.split('\x00')[0])
        non_sus_sections = len(set(tmp).intersection(benign_sections))
        result=[len(tmp) - non_sus_sections, non_sus_sections]
        return result


    def check_packer(self,filepath):
        result=[]
        matches = self.rules.match(filepath)
        if matches == {}:
            result.append([0,"NoPacker"])
        else:
            result.append([1,matches['main'][0]['rule']])
        return result

    def get_text_data_entropy(self,pe):
        result=[0.0,0.0]
        for section in pe.sections:
            s_name = section.Name.split('\x00')[0]
            if s_name == ".text":
                result[0]= section.get_entropy()
            elif s_name == ".data":
                result[1]= section.get_entropy()
            else:
                pass
        return result  

    def get_file_bytes_size(self,filepath):
        f = open(filepath, "rb")
        byteArr = map(ord, f.read())
        f.close()
        fileSize = len(byteArr)
        return byteArr,fileSize

    def cal_byteFrequency(self,byteArr,fileSize):
        freqList = []
        for b in range(256):
            ctr = 0
            for byte in byteArr:
                if byte == b:
                    ctr += 1
            freqList.append(float(ctr) / fileSize)
        return freqList

    def get_file_entropy(self,filepath):
        byteArr, fileSize = self.get_file_bytes_size(filepath)
        freqList = self.cal_byteFrequency(byteArr,fileSize)
        # Shannon entropy
        ent = 0.0
        for freq in freqList:
            if freq > 0:
                ent +=  - freq * math.log(freq, 2)

            #ent = -ent
        return [fileSize,ent]
    
    def get_fileinfo(self,pe):
        result=[]
        try:
            FileVersion    = pe.FileInfo[0].StringTable[0].entries['FileVersion']
            ProductVersion = pe.FileInfo[0].StringTable[0].entries['ProductVersion']
            ProductName =    pe.FileInfo[0].StringTable[0].entries['ProductName']
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
        return int ( result[0] != 'error')

    def write_csv_header(self):
        filepath = self.output
        header= self.IMAGE_DOS_HEADER + self.FILE_HEADER + self.OPTIONAL_HEADER + self.Derived_header
        header.append("class")
        csv_file= open(filepath,"wa")
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(header)
        csv_file.close()

    def extract_all(self,filepath):
        data =[]
        #load given file
        try:
            pe = pefile.PE(filepath)
        except Exception, e:
            print "{} while opening {}".format(e,filepath)
        else:
            data += self.extract_dos_header(pe)
            data += self.extract_file_header(pe)
            data += self.extract_optional_header(pe)
            # derived features
            #number of suspicisou sections and non-suspicsious section
            num_ss_nss = self.get_count_suspicious_sections(pe)
            data += num_ss_nss
            # check for packer and packer type
            packer = self.check_packer(filepath)
            # Appending the packer info to the rest of features
            data += packer[0]
            entropy_sections = self.get_text_data_entropy(pe)
            data += entropy_sections
            f_size_entropy = self.get_file_entropy(filepath)
            data += f_size_entropy
            fileinfo = self.get_fileinfo(pe)
            data.append(fileinfo)
            data.append(self.type)
        
        return data
    
    def write_csv_data(self,data):
        filepath = self.output
        csv_file= open(filepath,"a")
        writer = csv.writer(csv_file, delimiter=',')
        writer.writerow(data)
        csv_file.close()
    

    def create_dataset(self):
        self.write_csv_header()
        #run through all file of source and extract features
        for file in os.listdir(self.source):         
                filepath = self.source + file
                data = self.extract_all(filepath)
                self.write_csv_data(data)
                print "Successfully Data extracted and written for {}.".format(file)

def main():    
    source_path= raw_input("Enter the path of samples (ending with /) >>  ")
    output_file= raw_input("Give file name of output file. (.csv) >>")
    label = raw_input("Enter type of sample( malware(1)|benign(0))>>")

 #Example of input

    #source_path = "/home/user/ClaMP/test-data/"
    #output_file = "/home/user/ClaMP/dataset.csv"    
    #label = 0    

    features = pe_features(source_path,output_file,label)    
    features.create_dataset()
    
if __name__ == '__main__':
    main()

