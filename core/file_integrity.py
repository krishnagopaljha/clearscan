import os
import hashlib
import requests

def get_file_hash(file_path, hash_algorithm='sha256'):
    """Compute the hash of the file."""
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print("Error: File not found.")
        return None

def check_virustotal(api_key, file_hash):
    """Query VirusTotal API with the file hash."""
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_hash}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print("Error querying VirusTotal API.")
        return None

def main():
    """Main function for file integrity checker."""
    file_path = input("Enter the path to the file: ").strip()
    api_key = input("Enter your VirusTotal API key: ").strip()

    if not os.path.isfile(file_path):
        print("Error: File path is incorrect.")
        return

    # Calculate the file's hash
    file_hash = get_file_hash(file_path)
    if not file_hash:
        return

    # Check the hash with VirusTotal
    print(f"Checking {file_hash} with VirusTotal...")
    report = check_virustotal(api_key, file_hash)
    
    if report:
        if report['response_code'] == 1:
            print("Scan Results:")
            print(f"  File Hash: {report['resource']}")
            print(f"  Total Detections: {report['positives']} / {report['total']}")
            print(f"  VirusTotal Permalink: {report['permalink']}")
        else:
            print("No results found on VirusTotal for this file.")
    else:
        print("Error retrieving data from VirusTotal.")

if __name__ == "__main__":
    main()
