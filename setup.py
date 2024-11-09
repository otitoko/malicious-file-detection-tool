import os
from git import Repo

vt_api_key = input("Enter Virustotal API key: ")

print("Writing API key to .env file...")

f = open(".env", "w")
f.write(f"vt_api_key={vt_api_key}\n")
f.close()

print("The automatic test environment comes preloaded with several files and directories, two of which are zipped malware files.")
print("Do you wish to automatically create the test environment for scanning?")


answer = input("y/n\n")
while answer not in ('y', 'n'):
    print("Inavlid Input. Do you wish to automatically create the test environment for scanning?")
    answer = input("y/n\n")

setup_script_path = os.path.dirname(os.path.realpath(__file__))
test_dir_path = f"{setup_script_path}/malware_scanner_test_dir"

if answer == 'y':
   Repo.clone_from("https://github.com/otitoko/malware_scanner_test_dir.git",test_dir_path) 
else:
    os.mkdir(test_dir_path)

f = open(".env", "a")
f.write(f"test_dir_path={test_dir_path}/depth_zero_directory")
f.close()
