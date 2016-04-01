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

1. Malware-2722_hash_size_entropy.csv  

    This file have filename (Hash) , filesize in bytes, and Entropy of each malware sample a Total of 2722.

2. Clean-2501_name_size_entropy.csv  

    This file have filename, filesize in bytes, and Entropy of each clean sample, which where collected after fresh installed Windows OS (XP and Windows7) a Total of 2501.


# Scripts files

1. calculate_size_and_entropy.py

    This python script will calculate size and entropy of all files present in given directory and will write these information with file name to a .csv file.
