import os, hashlib, requests,time, vt
from dotenv import load_dotenv

load_dotenv()

files = []
unknown_files = []

api_key = os.getenv("vt_api_key")
client = vt.Client(f"{api_key}")

#Hash file with SHA1, return the hash
def hash_file(file):
    with open(file,"rb") as file:
        digest = hashlib.file_digest(file, "sha1")
        return digest.hexdigest()



#Scan directory from a specified path, root_dir.
#The scan is depth first. A list, stack, is created, which acts like a stack for keeping track of which directories need to be scanned
#scandir() does its thing of scanning the directory.
#If the scanned entity is a directory, it gets added to stack, if not, it gets added to the files list.
def scan_directory(root_dir):
    stack = [root_dir]
    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    print(entry)
                    if entry.is_dir():
                        stack.append(entry.path)
                    else:
                        files.append(entry)
        except PermissionError:
            continue

    return files


#Hash and send the specified file to the url which scans for the hashes existence in a few dbs, most importantly NIST's NSRL
#If the file exists in a db and has a trust rating of more than 75 we do nothing with it
#Otherwise it gets appended to the unknown_files list for additional scanning
def hash_check(file):
    hash = hash_file(file)
    url = f"https://hashlookup.circl.lu/lookup/sha1/{hash}"

    response = requests.get(url)
    data = response.json()

    if response.status_code == 200 and data["hashlookup:trust"]>75:
        print(f"Request success with status code {response.status_code}")
        return response.json()
    else:
        print(f"Request failed with status code {response.status_code}")
        unknown_files.append(file)
        return None



#File file gets sent to Virustotal to be scanned.
#When the scan is complete the statistics from the scan get printed
def vt_scan(file):
    with open(file,"rb") as file:
        analysis = client.scan_file(file)
    while True:
        analysis = client.get_object("/analyses/{}", analysis.id)
        if analysis.status == "completed":
            print(analysis.stats)
            break
        time.sleep(30)

