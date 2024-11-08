import os, hashlib, requests, json, sys, vt,time
from dotenv import load_dotenv

load_dotenv()

url = "https://www.virustotal.com/api/v3/files"

api_key = os.getenv("vt_api_key")
client = vt.Client(f"{api_key}")

directory = "./test"

try:
    if sys.argv[1] != None:
        directory = sys.argv[1]
except:
    print("No path specified, defaulting to ./test: ")



files = []
unknown_files = []

headers = {
    "accept": "application/json",
    "x-apikey": api_key,
    "content-type": "multipart/form-data"
}

def hash_file(file):
    with open(file,"rb") as file:
        digest = hashlib.file_digest(file, "sha1")
        return digest.hexdigest()




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
                        files.append(entry)
        except PermissionError:
            continue

    return files


def bulk_hash_check(hashes):
        
        url = "https://hashlookup.circl.lu/bulk/sha1"

        data = {
            "hashes": hashes
            }
        response = requests.post(url,json=data)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Request failed with status code {response.status_code}")
            return None

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


def vt_scan(file):
    with open(file.path,"rb") as file:
        analysis = client.scan_file(file)
    while True:
        analysis = client.get_object("/analyses/{}", analysis.id)
        print(analysis.status)
        if analysis.status == "completed":
            print(analysis.stats)
            break
        time.sleep(30)



hashes = scan_directory(directory)

for hash in hashes:
    hash_check(hash)

print(unknown_files)
for file in unknown_files:
    analysis = vt_scan(file)




client.close()
