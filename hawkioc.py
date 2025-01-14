import os
import re
import json
import hashlib
import requests
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from pyfiglet import Figlet
import pandas as pd
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# Display ASCII Art
def display_ascii_art():
    program_name = "HawkIoC"
    ascii_art = Figlet(font='slant').renderText(program_name)
    print(ascii_art)
    credits = "\nCreated by: pnasis\nVersion: v1.0\n"
    print(credits)

# Load IOC Signatures from File
def load_iocs(file="ioc.json"):
    if not os.path.exists(file):
        raise FileNotFoundError(f"IOC file {file} not found.")
    with open(file, "r") as f:
        return json.load(f)

# Match IOCs in File
def match_iocs(file_path, iocs):
    matches = {"hashes": [], "ips": [], "domains": [], "urls": []}
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Hash Matching
        file_hash = hashlib.md5(data).hexdigest()
        if file_hash in iocs.get("hashes", []):
            matches["hashes"].append(file_hash)

        # IP Matching
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for ip in re.findall(ip_pattern, data.decode(errors="ignore")):
            if ip in iocs.get("ips", []):
                matches["ips"].append(ip)

        # Domain Matching
        domain_pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        for domain in re.findall(domain_pattern, data.decode(errors="ignore")):
            if domain in iocs.get("domains", []):
                matches["domains"].append(domain)

        # URL Matching
        url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        for url in re.findall(url_pattern, data.decode(errors="ignore")):
            if url in iocs.get("urls", []):
                matches["urls"].append(url)
    except Exception as e:
        logging.warning(f"Error processing {file_path}: {e}")
    return matches

# Scan Files in Directory Using Multi-threading
def scan_files_in_directory(directory, iocs, max_threads=4):
    matches = []
    with ThreadPoolExecutor(max_threads) as executor:
        file_paths = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        for result in tqdm(executor.map(lambda path: match_iocs(path, iocs), file_paths), total=len(file_paths), desc="Scanning Files"):
            matches.append(result)
    return matches

# Fetch IOCs from VirusTotal
def fetch_iocs_from_virustotal(api_key):
    url = "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        iocs = {"hashes": [], "ips": [], "domains": []}
        for rule in data.get("data", []):
            if rule["attributes"].get("ruleset_id"):
                indicators = rule["attributes"].get("indicators", [])
                for indicator in indicators:
                    if indicator["type"] == "file":
                        iocs["hashes"].append(indicator["value"])
                    elif indicator["type"] == "ip_address":
                        iocs["ips"].append(indicator["value"])
                    elif indicator["type"] == "domain":
                        iocs["domains"].append(indicator["value"])
        return iocs
    else:
        raise RuntimeError(f"Error fetching IOCs from VirusTotal: {response.status_code}")

# Generate Report
def generate_report(matches, output_file="report.csv"):
    df = pd.DataFrame(matches)
    df.to_csv(output_file, index=False)
    print(f"Report saved to {output_file}")

# Visualize Results
def visualize_results(matches):
    match_counts = {
        "Hashes": sum(len(m["hashes"]) for m in matches),
        "IPs": sum(len(m["ips"]) for m in matches),
        "Domains": sum(len(m["domains"]) for m in matches),
        "URLs": sum(len(m["urls"]) for m in matches),
    }
    plt.bar(match_counts.keys(), match_counts.values())
    plt.title("IOC Match Summary")
    plt.xlabel("IOC Type")
    plt.ylabel("Count")
    plt.show()

# Main Function
def main():
    display_ascii_art()

    while True:
        print("\n1. Load IOCs from File")
        print("2. Fetch IOCs from VirusTotal")
        print("3. Scan Directory for IOCs")
        print("4. Generate and Visualize Report")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            ioc_file = input("Enter the path to the IOC file (e.g., ioc.json): ")
            try:
                iocs = load_iocs(ioc_file)
                print("IOCs loaded successfully.")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "2":
            api_key = input("Enter your VirusTotal API key: ")
            try:
                iocs = fetch_iocs_from_virustotal(api_key)
                print("IOCs fetched successfully from VirusTotal.")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "3":
            directory = input("Enter the directory to scan: ")
            try:
                matches = scan_files_in_directory(directory, iocs)
                print("Scanning complete.")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "4":
            try:
                output_file = input("Enter the output file name for the report (e.g., report.csv): ")
                generate_report(matches, output_file)
                visualize_results(matches)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "5":
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
