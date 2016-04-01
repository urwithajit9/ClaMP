# ClaMP (Classification of Malware with PE headers)
A Malware classifier dataset built with header fields’ values of Portable Executable files
# Dataset files
1. ClaMP_Integrated-5184.arff
	- Total samples	: 5184 (Malware () + Benign())
	- Features (69)	: Raw Features (54) + Derived Features(15)
2. ClaMP_Raw-5184.arff
	- Total samples	: 5184 (Malware ()+ Benign())
	- Features (55)	: Raw Features(55)

3. ClaMP_Integrated-5184.csv
	- Total samples	: 5184 (Malware () + Benign())
	- Features (69)	: Raw Features (54) + Derived Features(15)
4. ClaMP_Raw-5184.csv
	- Total samples	: 5184 (Malware ()+ Benign())
	- Features (55)	: Raw Features(55)

# Raw samples metadata information
1. Clean_md5_2917.csv

    This file have filename,MD5 hash and size for all clean samples (2917) collected for experiment.

2. Malware_md5_2917.csv    

    This file have filename,MD5 hash and size for all malware samples (2917) collected for experiment.

3. Clean_md5_without_dup_2873.csv
     This file have filename,MD5 hash and size without any duplicate clean samples (2873).

4. Malware_md5_without_dup_2873.csv   

     This file have filename,MD5 hash and size without any duplicate clean samples (2873).
5. Malware-2722_hash_size_entropy.csv  

    This file have filename (Hash) , filesize in bytes, and Entropy of each malware sample a Total of 2722.

6. Clean-2501_name_size_entropy.csv  

    This file have filename, filesize in bytes, and Entropy of each clean sample, which where collected after fresh installed Windows OS (XP and Windows7) a Total of 2501.

7. Clean_VT_report-2873.csv    
    This file have Virus Total report of all clean samples (without duplicate, 2873). File                contains information like, ID,fileName,MD5Hash,Total,Positive,Type-TrendMicro,Type-F-secure,Scan-Date.

8.  Clean_NOT_PE_6.txt  

      This file have list of clean files which are not Portable Executable (PE) file format.

9.  Malware_VT_report_without_Zipped_3817.csv  

    This file have Virus Total report of all malware samples (with some zipped that is not used in analysis, 3817). File contains information like,
    MD5hash,Total,Positive,TrendMicro,F-Secure,McAfee,Symantec,Avast,Kaspersky,BitDefender,Sophos,GData,Panda,Qihoo-360,Scan-Date



# Scripts files

1. move_duplicate_files.py
    This python script will move the duplicates files based on their MD5 and will give file information report as CSV file. ( Look into script header for detail working)

2. calculate_size_and_entropy.py

    This python script will calculate size and entropy of all files present in given directory and will write these information with file name to a .csv file.
