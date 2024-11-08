#TODO
#1. print the info all at once with the respective name of the file
#2. separate the functions into files

import os, sys
from dotenv import load_dotenv
import functions


load_dotenv()


directory = "./test"

try:
    if sys.argv[1] != None:
        directory = sys.argv[1]
except:
    print("No path specified, defaulting to ./test: ")


files = functions.scan_directory(directory)

for entry in files:
    functions.hash_check(entry)

    


unknown_files_arc = functions.zip_files(functions.unknown_files)

analysis = functions.vt_scan(entry)


unknown_files_arc_path = "./unknown_files_arc.zip"
os.remove(unknown_files_arc_path)
functions.client.close()
