#TODO
#1. print the info all at once with the respective name of the file
#2. separate the functions into files

import os, sys
from dotenv import load_dotenv
import functions


load_dotenv()


directory = os.getenv("test_dir_path")

try:
    if sys.argv[1] != None:
        directory = sys.argv[1]
except:
    print("No path specified, defaulting to ./malware_scanner_test_dir: ")


files = functions.scan_directory(directory)

for entry in files:
    functions.hash_check(entry)

    



for entry in functions.unknown_files:
    print(entry)
    analysis = functions.vt_scan(entry)


functions.client.close()
