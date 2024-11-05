#DONE. scan fs -> how?
# go from root and go through each file, breadth or depth first, and hash it



#2. use look up database, eg. NIST NSRL
#3. upload remaining files to Virustotal via api

#4. VM (optional)

#break this up:
#first scan directory
#then directory recursively for other directories
#try it from root dir

import os, hashlib
directory = "/home/lain/school/appsec/malicious-file-detection-tool"
def hash_file(file):
    with open(file,"rb") as file:
        digest = hashlib.file_digest(file, "sha1")
        return digest.hexdigest()

#def compare_hash(file):
#    if hash_file(file)



def scan_directory(root_dir):
    stack = [root_dir]
    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if entry.is_dir():
                        stack.append(entry.path)
                    else:
                        print(hash_file(entry))
        except PermissionError:
            continue




scan_directory(directory)



