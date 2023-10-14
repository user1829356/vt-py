# 🦠 VirusTotal Python Scanner

This Python script allows you to perform scans on files, URLs, or IP addresses using the [VirusTotal](https://www.virustotal.com/) API. It can be used to check the reputation and analysis results of various entities.

## 🚀 Prerequisites

Before using this script, make sure you have:

- A [VirusTotal API key](https://developers.virustotal.com/reference#getting-started) (replace `'YOUR_API_KEY'` in the script with your actual API key).
- Python 3 installed on your system.

## 📖 Usage

To use the script, follow these steps:

1. Clone the repository or download the script.

2. Open your terminal and navigate to the directory where the script is located.

3. Run the script with the appropriate options:

   ```bash
   python3 vt-py.py -[hash|url|ip] path/to/file.txt

4. Replace -[hash|url|ip] with one of the following options:

    - hash: For scanning hash values.

    - url: For scanning URLs.

    - ip: For scanning IP addresses.

5. Replace path/to/file.txt with the path to the file containing the entities you want to scan. Each entity should be on a separate line.

The script will perform the scans and generate a CSV file with the results. The CSV file will be named results_<timestamp>.csv, where <timestamp> is the current date and time.

## 📋 Output

The generated CSV file will contain the following columns:

For -hash option:

  - SHA-256
  
  - SHA-1
  
  - MD5
  
  - Date (Last analysis date)
  
  - Scanned Hash
  
  - Vendor-specific scan results

For -url option:
  
  - URL
  
  - Date (Last analysis date)
  
  - Scanned URL
  
  - Vendor-specific scan results

For -ip option:
  
  - IP
  
  - Scanned IP
  
  - Vendor-specific scan results

## 📚 Closing Remarks

Remember to keep your VirusTotal API key secure, and do not share it publicly. This script can be a useful tool for quickly checking the reputation of various entities, but it should be used responsibly and in compliance with VirusTotal's terms of service.

## 🌟 Example

Here's an example of how to use the script to scan a list of hash values:


```bash
python3 vt-py.py -hash my_hash_list.txt
