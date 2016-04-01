#A Simple shell script to use Linux's file command to test file type of all files in given directory
for i in /home/user/ClaMP/test-data/*
do
    file "$i" >> "/home/user/ClaMP/test-data/filetype.txt"
done
