# Digital Signature Integrity Scanner

This program detects and results in the reliability of Digital Signatures by scanning specified directories, extracting file creation and last-modified timestamps, generating and comparing hashes to verify file integrity, and it reports whether digital signatures are reliable or potentially malicious. 

## The Features
Single File Scanning – Analyze an individual file for malicious indicators

Directory Scanning – Recursively scan all files within a directory

SHA-256 Hashing – Secure hash generation using Python’s _hashlib_

VirusTotal API Integration – Real-time malware detection using _VirusTotal_

Local Malicious Hash Fallback – Detect threats even if API requests fail

Formatted – Organized using _PrettyTable_

Time Tracking – Displays total scan duration

## How it works
The program calculates a file’s SHA-256 hash and the hash is submitted to the VirusTotal API.

If the API detects malicious activity, the file is flagged as Malicious.
If the API fails, a local malicious hash set is used as a fallback.

Results are then displayed in a color-coded table:

&nbsp;&nbsp;Red = Malicious

&nbsp;&nbsp;Green = Clean

&nbsp;&nbsp;Unknown = No data available
