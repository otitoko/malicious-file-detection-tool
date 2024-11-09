import os, sys
from dotenv import load_dotenv
import functions


load_dotenv()


directory = os.getenv("test_dir_path")

#if no specified path for which directory to scan, then default to the default
try:
    if sys.argv[1] != None:
        directory = sys.argv[1]
except:
    print("No path specified, defaulting to ./malware_scanner_test_dir: ")


#scan_directory does its thing and returns a list which gets called files
files = functions.scan_directory(directory)

#for each entry in the files list, check the hash in the dbs used by circ.lu
for entry in files:
    functions.hash_check(entry)

#for each entry in unknown_files print the name of the entry and send it off to virustotal for the scan
for entry in functions.unknown_files:
    print(entry)
    analysis = functions.vt_scan(entry)


#dont forget to close the client :)
functions.client.close()
