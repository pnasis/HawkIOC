import os
import json
import requests
from datetime import datetime

# Path to the IOC JSON file
IOC_FILE = "ioc.json"

# VirusTotal API Key (replace with your API key)
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"

# Open threat intelligence feeds
THREAT_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
]


def fetch_virus_total_hashes():
    """Fetch known malicious hashes from VirusTotal."""
    url = "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # Parse response to extract hashes
        data = response.json()
        hashes = [item["attributes"]["id"] for item in data["data"]]
        return hashes
    except Exception as e:
        print(f"Error fetching VirusTotal hashes: {e}")
        return []


def fetch_open_threat_feeds():
    """Fetch IOCs from open threat intelligence feeds."""
    ips, domains, urls = set(), set(), set()

    for feed in THREAT_FEEDS:
        try:
            response = requests.get(feed)
            response.raise_for_status()
            lines = response.text.splitlines()

            for line in lines:
                # Basic categorization of IOCs
                if line.startswith("#") or not line.strip():
                    continue
                if "." in line and "/" in line:
                    if "http" in line:
                        urls.add(line.strip())
                    else:
                        ips.add(line.strip())
                elif "." in line:
                    domains.add(line.strip())

        except Exception as e:
            print(f"Error fetching threat feed {feed}: {e}")

    return list(ips), list(domains), list(urls)


def update_ioc_file():
    """Update the IOC JSON file."""
    # Fetch current IOCs
    hashes = fetch_virus_total_hashes()
    ips, domains, urls = fetch_open_threat_feeds()

    # Create IOC structure
    iocs = {
        "hashes": hashes,
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "last_updated": datetime.now().isoformat()
    }

    # Update or create the IOC JSON file
    try:
        with open(IOC_FILE, "w") as f:
            json.dump(iocs, f, indent=4)
        print(f"IOC file updated successfully: {IOC_FILE}")
    except Exception as e:
        print(f"Error writing IOC file: {e}")


if __name__ == "__main__":
    update_ioc_file()
