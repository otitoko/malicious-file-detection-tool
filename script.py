import os, hashlib, requests, json, sys, vt
from dotenv import load_dotenv

load_dotenv()

url = "https://www.virustotal.com/api/v3/files"

api_key = os.getenv("vt_api_key")
client = vt.Client(api_key)

directory = "./test"

try:
    if sys.argv[1] != None:
        directory = sys.argv[1]
except:
    print("No path specified, defaulting to ./test: ")



hashes = []
unknown_hashes = []

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
                        hashes.append(hash_file(entry))
        except PermissionError:
            continue

    return hashes


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

def hash_check(hash):
    url = f"https://hashlookup.circl.lu/lookup/sha1/{hash}"

    response = requests.get(url)
    if response.status_code == 200:
        print(f"Request success with status code {response.status_code}")
        return response.json()
    else:
        print(f"Request failed with status code {response.status_code}")
        unknown_hashes.append(hash)
        return None

def vt_scan(file):
    with open(file,"rb") as file:
        analysis = client.scan_file(file)

    return analysis





hashes = scan_directory(directory)

for hash in hashes:
    hash_check(hash)

print(unknown_hashes)



#if response:
#    print(json.dumps(response, indent=4))


command = f"curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey='{api_key}'  -d 'resource={payload}'"

#os.system(command)
