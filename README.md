Malicious File Detection Tool

This tool provides a robust method for detecting potentially malicious files on your system. It recursively scans directories (depth-first), checks found files against the NIST RDS (National Institute of Standards and Technology Reference Data Set) for known safe files, and sends any unknown or untrusted files to VirusTotal for additional scanning via its API.
Features

    Directory Scanning: Recursively scans specified directories for files.
    NIST RDS Check: Cross-references files with the NIST RDS to filter known safe files.
    VirusTotal Integration: Sends unknown or suspicious files to VirusTotal for analysis.
    Efficient: Uses aiohttp for asynchronous HTTP requests, ensuring responsive performance during scanning.

Requirements

To use this tool, you'll need the following:

    VirusTotal API Key: Required for VirusTotal integration.
    Python 3.8+: Python 3.8 or later is recommended.

Python Package Dependencies

Install the following packages for this tool to work correctly:
Package	Version
aiohappyeyeballs	2.4.3
aiohttp	3.10.10
aiosignal	1.3.1
attrs	24.2.0
certifi	2024.8.30
charset-normalizer	3.4.0
dnspython	2.7.0
frozenlist	1.5.0
gitdb	4.0.11
GitPython	3.1.43
idna	3.10
multidict	6.1.0
pip	23.0.1
propcache	0.2.0
pyhashlookup	1.2.5
python-dotenv	1.0.1
requests	2.32.3
setuptools	66.1.1
smmap	5.0.1
urllib3	2.2.3
vt-py	0.18.4
yarl	1.17.1
Installation
1. Clone the Repository

git clone https://github.com/your-username/malicious-file-detection-tool.git
cd malicious-file-detection-tool

2. Install Dependencies

To install the required dependencies, run:

pip install -r requirements.txt

3. Set Up Your Environment

Ensure that you have a VirusTotal API key. Save this key in a .env file in the project directory as follows:

VIRUSTOTAL_API_KEY=your_api_key_here

Usage

    Run Setup

    Execute setup.py to configure the environment and validate your VirusTotal API key:

python setup.py

Run the Scanner

Start the file scanning process by running script.py:

    python script.py

The script will then begin scanning, cross-checking files with NIST RDS, and sending suspicious files to VirusTotal.
