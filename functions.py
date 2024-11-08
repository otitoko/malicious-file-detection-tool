import os, hashlib, requests,time, tarfile, zipfile, vt
from dotenv import load_dotenv

load_dotenv()

files = []
unknown_files = []

api_key = os.getenv("vt_api_key")
client = vt.Client(f"{api_key}")

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
    with open(file,"rb") as file:
        analysis = client.scan_file(file)
    while True:
        analysis = client.get_object("/analyses/{}", analysis.id)
        print(analysis.status)
        if analysis.status == "completed":
            print(analysis.stats)
            break
        time.sleep(30)


def zip_files(unknown_files):
    archive_name = "unknown_files_arc.zip"

    # Open the archive in write mode
    with zipfile.ZipFile(archive_name, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
        for file in unknown_files:
            archive.write(file)  # Add each file to the .zip archive
            print(f"Added {file} to {archive_name}")

    return archive_name 
