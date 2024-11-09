TODO:
 1. further separate the functions and put into their own files
 2. create a setup script to download and create the test directory along with all the files
 3. add documentation
 4. beautify readme

A malicious file detection tool. It does what it says.

It recursively scans the specified directory depth first, checks the found files on NIST RDS and any unknown or untrustworthy files get sent to Virustotal via API for further scanning.


Requirements:
    
    VirusTotal API key 
    
aiohappyeyeballs   2.4.3
aiohttp            3.10.10
aiosignal          1.3.1
attrs              24.2.0
certifi            2024.8.30
charset-normalizer 3.4.0
dnspython          2.7.0
frozenlist         1.5.0
gitdb              4.0.11
GitPython          3.1.43
idna               3.10
multidict          6.1.0
pip                23.0.1
propcache          0.2.0
pyhashlookup       1.2.5
python-dotenv      1.0.1
requests           2.32.3
setuptools         66.1.1
smmap              5.0.1
urllib3            2.2.3
vt-py              0.18.4
yarl               1.17.1

Setup:
    
    Run setup.py

    Run script.py
