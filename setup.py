import os,subprocess
from git import Repo

vt_api_key = input("Enter Virustotal API key: ")

#write api to .env
print("Writing API key to .env file...")
f = open(".env", "w")
f.write(f"vt_api_key={vt_api_key}\n")
f.close()

print("The automatic test environment comes preloaded with several files and directories, two of which are zipped malware files.")
print("Do you wish to automatically create the test environment for scanning?")


#loop to ensure proper input
clone_answer = input("y/n\n")
while clone_answer not in ('y', 'n'):
    print("Inavlid Input. Do you wish to automatically create the test environment for scanning?")
    clone_answer = input("y/n\n")

setup_script_path = os.path.dirname(os.path.realpath(__file__))
test_dir_path = f"{setup_script_path}/malware_scanner_test_dir"

#clone github repo if answer is yes, create empty directory if no
if clone_answer == 'y':
    try:
        Repo.clone_from("https://github.com/otitoko/malware_scanner_test_dir.git",test_dir_path) 
        #write path of the test directory to .env
        f = open(".env", "a")
        f.write(f"test_dir_path={test_dir_path}/depth_zero_directory")
        f.close()
    except:
        print("Directory malware_scanner_test_dir already exists")
else:
    try:
        os.mkdir(f"test_dir_path")
        f = open(".env", "a")
        f.write(f"test_dir_path={test_dir_path}")
        f.close()
    except:
        print("Directory malware_scanner_test_dir already exists")




path_to_pip = "pip"
path = input("Specify path to pip. (leave blank and run as super user if not using virtual environment)\n")

if path != None:
    path_to_pip = path

f = open("pkg.txt")

for line in f:
    pkg = line.strip()
    command = [path_to_pip, "install", pkg] 
    subprocess.run(command)
