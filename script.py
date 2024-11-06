#DONE. scan fs -> how?
# go from root and go through each file, breadth or depth first, and hash it



#2. use look up database, eg. NIST NSRL
#3. upload remaining files to Virustotal via api

#4. VM (optional)

import os, hashlib, requests
from dotenv import load_dotenv

load_dotenv()

url = "https://www.virustotal.com/api/v3/files"

api_key = os.getenv("vt_api_key")
directory = "/home/lain/school/appsec/malicious-file-detection-tool"
payload = "/home/lain/school/appsec/malicious-file-detection-tool/script.py"

headers = {
    "accept": "application/json",
    "x-apikey": api_key,
    "content-type": "multipart/form-data"
}

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

#def upload_file(file):


scan_directory(directory)


response = requests.post(url,data=payload, headers=headers)

print(response.text)

os.system("curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=817571839de6081eef21d13cd3ddbe611ae6e18902a3b3849f8b944860363af1  -d 'resource="+payload+"'")
