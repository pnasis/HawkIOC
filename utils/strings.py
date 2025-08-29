# -*- coding: utf-8 -*-
"""
String extraction helpers (ASCII & UTF-16LE).
"""

import re
import string
from utils.common import xor_decrypt


def extract_strings(file_path, min_length=4):
    """Extract ASCII and UTF-16LE strings from a file."""
    with open(file_path, "rb") as fobj:
        data = fobj.read()

    strings = []
    current = []

    for byte in data:
        if 32 <= byte < 127:  # printable ASCII range
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def save_strings_to_file(strings, file_path):
    """Save extracted strings to '<file>_strings.txt'."""
    output_file = f"{file_path}_strings.txt"
    with open(output_file, "w", encoding="utf-8") as fobj:
        for line in strings:
            fobj.write(line + "\n")
    return output_file

def categorize_strings(strings):
    """
    Categorize strings into URLs, IPs, API calls, etc.
    """
    categories = {
        "urls": [],
        "domains": [],
        "ips": []
    }

    url_pattern = re.compile(r"(https?://[^\s\"'<>]+)")
    domain_pattern = re.compile(r"\b((?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,63}))\b")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    excluded_extensions = {"dll", "tmp", "exe", "dat", "bin", "sys"}
    for s in strings:
        if url_pattern.search(s):
            categories["urls"].append(s)
        elif domain_pattern.fullmatch(s):
            tld = s.split(".")[-1].lower()
            if tld not in excluded_extensions and not ip_pattern.match(tld):
                categories["domains"].append(s)
        elif ip_pattern.search(s):
            categories["ips"].append(s)

    return categories

def brute_force_xor_strings(file_path):
    """
    Brute-force single-byte XOR to spot likely C2/commands.
    Heuristic: print alert if decrypted buffer contains common markers.
    """
    with open(file_path, "rb") as fobj:
        data = fobj.read()

    markers = [b"http", b"https", b"cmd.exe", b"powershell", b"/bin/sh"]
    for key in range(1, 256):
        dec = xor_decrypt(data, key)
        if any(m in dec for m in markers):
            print(f"[ALERT] Possible XOR-encoded strings found with key {key}!")
