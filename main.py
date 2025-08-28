#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HawkIoC - Malware Static Analysis Automation Tool
"""

import argparse
import os
import sys
import warnings

from pyfiglet import Figlet

from utils.common import print_section
from utils.file_info import (
    get_file_type,
    calculate_hashes,
    get_fuzzy_hash,
)
from utils.strings import extract_strings, save_strings_to_file
from utils.yara_scanner import run_yara
from core.factory import AnalyzerFactory
from utils.entropy import brute_force_xor_strings

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

warnings.simplefilter("ignore")


def parse_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="HawkIoC - Static Malware Analysis"
    )
    parser.add_argument(
        "-f", "--file", required=True, help="File to analyze"
    )
    parser.add_argument("--yara", help="YARA rule file")
    return parser.parse_args()


def banner():
    """Print tool banner."""
    print(Figlet(font="slant").renderText("HawkIoC"))
    print("\nCreated by: pnasis\nVersion: v2.1\n")


def main():
    """Main entry point."""
    args = parse_args()

    if not os.path.exists(args.file):
        print("[ERROR] File not found! Exiting..")
        sys.exit(1)

    banner()
    print("[INFO] Analyzing:", args.file)

    # File information
    print_section("File Information")
    file_type, magic_numbers = get_file_type(args.file)
    print(f"[INFO] File Type: {file_type}")
    print(f"[INFO] Magic Numbers: {magic_numbers}")

    # Hashes
    print_section("File Hashes")
    md5_hash, sha256_hash = calculate_hashes(args.file)
    print(f"[INFO] MD5: {md5_hash}")
    print(f"[INFO] SHA256: {sha256_hash}")

    # Fuzzy hashing
    print_section("Fuzzy Hashing (SSDEEP)")
    try:
        print(f"[INFO] SSDEEP: {get_fuzzy_hash(args.file)}")
    except Exception as exc:
        print(f"[WARNING] SSDEEP failed: {exc}")

    # Strings
    print_section("Extracting Strings")
    extracted = extract_strings(args.file)
    print(f"[INFO] Extracted {len(extracted)} strings.")
    out_path = save_strings_to_file(extracted, args.file)
    print(f"[INFO] Strings saved to: {out_path}")

    # Analyzer selection + run
    analyzer = AnalyzerFactory.create(args.file, file_type)
    if analyzer is None:
        print("[WARNING] Unsupported file type.")
    else:
        analyzer.analyze()

    # YARA (optional)
    if args.yara:
        print_section("YARA Analysis")
        print("[INFO] Running YARA rules...")
        run_yara(args.file, args.yara)

    # XOR-encoded strings heuristic
    print_section("XOR-encoded strings Analysis")
    print("[INFO] Checking for XOR-encoded strings...")
    brute_force_xor_strings(args.file)

    print("\n[INFO] Analysis completed!")


if __name__ == "__main__":
    main()
