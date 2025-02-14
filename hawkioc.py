from pyfiglet import Figlet
import argparse
import hashlib
import magic
import pefile
import ssdeep
import os
import sys
import re
import string
import math
import subprocess
from collections import Counter
import yara
import matplotlib.pyplot as plt
import warnings
warnings.simplefilter("ignore")


def print_section(title):
    print("\n" + "=" * 50)
    print(f"\t\t[{title}]")
    print("=" * 50)

def get_file_type(file_path):
    file_magic = magic.Magic()
    file_type = file_magic.from_file(file_path)
    with open(file_path, 'rb') as f:
        magic_numbers = f.read(8).hex().upper()
    return file_type, magic_numbers

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def get_pe_hashes(file_path):
    try:
        pe = pefile.PE(file_path)
        imphash = pe.get_imphash()

        section_hashes = {}
        for section in pe.sections:
            md5_section = hashlib.md5(section.get_data()).hexdigest()
            sha256_section = hashlib.sha256(section.get_data()).hexdigest()
            section_hashes[section.Name.decode().strip('\x00')] = {
                "MD5": md5_section,
                "SHA256": sha256_section
            }

        return imphash, section_hashes, pe
    except pefile.PEFormatError:
        return None, None, None

def get_fuzzy_hash(file_path):
    return ssdeep.hash_from_file(file_path)

def extract_strings(file_path, min_length=4):
    """Extract printable ASCII and Unicode strings from a binary file."""
    with open(file_path, "rb") as f:
        data = f.read()

    # ASCII strings
    ascii_strings = re.findall(f"[{re.escape(string.printable)}]{{{min_length},}}", data.decode(errors="ignore"))

    # Unicode strings (UTF-16 LE/BE)
    unicode_strings = re.findall(r"(?:[\x20-\x7E]\x00){%d,}" % min_length, data.decode("utf-16le", errors="ignore"))

    extracted_strings = ascii_strings + unicode_strings
    return extracted_strings

def save_strings_to_file(strings, file_path):
    output_file = f"{file_path}_strings.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for line in strings:
            f.write(line + "\n")
    return output_file

def calculate_entropy(data):
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def analyze_entropy(file_path, pe):
    with open(file_path, "rb") as f:
        file_data = f.read()

    file_entropy = calculate_entropy(file_data)
    print_section("Entropy Analysis")
    print(f"[INFO] File Entropy: {file_entropy:.4f}")

    packed = False
    if pe:
        print("\n[INFO] PE Section Entropy:")
        for section in pe.sections:
            section_data = section.get_data()
            section_entropy = calculate_entropy(section_data)
            print(f"    * {section.Name.decode().strip()}: {section_entropy:.4f}")

            if section_entropy > 7.0:
                packed = True

    if file_entropy > 7.0 or packed:
        print("\n[WARNING] High entropy detected! The file is likely packed.")
        return True
    else:
        print("\n[INFO] Entropy levels suggest the file is not packed.")
        return False

def is_upx_packed(file_path):
    """Check if the file is packed with UPX by scanning its sections."""
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            if b"UPX" in section.Name:
                return True
    except pefile.PEFormatError:
        return False
    return False

def unpack_upx(file_path):
    """Attempt to unpack a UPX-packed file."""
    base_name, ext = os.path.splitext(os.path.basename(file_path))
    unpacked_file = base_name + "_unpacked" + ext
    try:
        result = subprocess.run(["upx", "-d", "-o", unpacked_file, file_path], capture_output=True, text=True)
        if "Unpacked" in result.stdout:
            print(f"[INFO] Successfully unpacked: {unpacked_file}")
            return unpacked_file
        else:
            print("[ERROR] UPX unpacking failed!")
            print(result.stderr)
            return None
    except FileNotFoundError:
        print("[ERROR] UPX not found. Please install UPX to enable unpacking.")
        return None

def extract_resources(file_path):
    try:
        pe = pefile.PE(file_path)
        for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            print(f"[INFO] Found resource type: {resource.struct.Id}")
    except AttributeError:
        print("[INFO] No resources found.")

# Extract import functions
def extract_imports(file_path):
    pe = pefile.PE(file_path)
    print("[INFO] Imported Functions:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  - DLL: {entry.dll.decode()}")
        for imp in entry.imports:
            print(f"    * {imp.name.decode() if imp.name else 'Ordinal'}")

# Detect suspicious API calls
def detect_suspicious_imports(file_path):
    SUSPICIOUS_APIS = ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "RegOpenKeyExA", "RegSetValueExA", "RegQueryValueExA", "CreateFileA", "InternetReadFile", "CloseHandle", "InternetCloseHandle", "InternetOpenUrlA", "GetComputerNameA", "CreateProcessA"]
    pe = pefile.PE(file_path)
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and any(api in imp.name.decode() for api in SUSPICIOUS_APIS):
                print(f"[WARNING] Suspicious API Found: {imp.name.decode()}")

# Run YARA rules
def run_yara(file_path, yara_rule):
    result = subprocess.run(["yara", yara_rule, file_path], capture_output=True, text=True)
    print("[INFO] YARA Scan Results:\n", result.stdout)

# XOR decryption
def xor_decrypt(data, key):
    return bytes([b ^ key for b in data])

def brute_force_xor_strings(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    for key in range(1, 256):  # Try all 1-byte XOR keys
        decrypted = xor_decrypt(data, key)
        if b"http" in decrypted or b"cmd.exe" in decrypted:
            print(f"[ALERT] Possible XOR-encoded strings found with key {key}!")

# Plot entropy visualization
def plot_entropy(file_path):
    pe = pefile.PE(file_path)
    file_entropy = calculate_entropy(open(file_path, "rb").read())
    entropies = [file_entropy]
    labels = ["Full File"]
    for section in pe.sections:
        entropies.append(calculate_entropy(section.get_data()))
        labels.append(section.Name.decode().strip())
    #plt.rcParams["font.family"] = "Liberation Sans"
    plt.bar(labels, entropies, color="red")
    plt.xlabel("Sections")
    plt.ylabel("Entropy")
    plt.title("Entropy Analysis")
    plt.show()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="File to analyze")
    parser.add_argument("--yara", help="YARA rule file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("[ERROR] File not found! Exiting..")
        sys.exit(1)

    print(Figlet(font='slant').renderText("HawkIoC"))
    print("\nCreated by: pnasis\nVersion: v1.0\n")
    print("[INFO] Analyzing:", args.file)

    print_section("File Information")
    file_type, magic_numbers = get_file_type(args.file)
    print(f"[INFO] File Type: {file_type}")
    print(f"[INFO] Magic Numbers: {magic_numbers}")

    print_section("File Hashes")
    md5_hash, sha256_hash = calculate_hashes(args.file)
    print(f"[INFO] MD5: {md5_hash}")
    print(f"[INFO] SHA256: {sha256_hash}")

    imphash, section_hashes, pe = get_pe_hashes(args.file)
    if imphash:
        print_section("PE File Analysis")
        print(f"[INFO] IMPHASH: {imphash}")
        for section, hashes in section_hashes.items():
            print(f"[INFO] Section: {section}, MD5: {hashes['MD5']}, SHA256: {hashes['SHA256']}")

    print_section("Fuzzy Hashing (SSDEEP)")
    fuzzy_hash = get_fuzzy_hash(args.file)
    print(f"[INFO] SSDEEP: {fuzzy_hash}")

    packed = analyze_entropy(args.file, pe)

    if packed and is_upx_packed(args.file):
        print_section("UPX Detection & Unpacking")
        print("[INFO] UPX packer detected!")
        unpacked_file = unpack_upx(args.file)
        if unpacked_file:
            print(f"[INFO] Re-analyzing unpacked file: {unpacked_file}")
            main()

    print_section("Extracting Strings")
    extracted_strings = extract_strings(args.file)
    base_name, ext = os.path.splitext(os.path.basename(args.file))
    output_file = save_strings_to_file(extracted_strings, base_name)
    print(f"[INFO] Extracted {len(extracted_strings)} strings.")
    print(f"[INFO] Strings saved to: {output_file}")

    print("[INFO] Extracting PE Resources...")
    extract_resources(args.file)

    print_section("Import Functions")
    print("[INFO] Extracting Import Functions...")
    extract_imports(args.file)

    print_section("Suspicious API Calls")
    print("[INFO] Checking for Suspicious API Calls...")
    detect_suspicious_imports(args.file)

    if args.yara:
        print_section("YARA Analysis")
        print("[INFO] Running YARA rules...")
        run_yara(args.file, args.yara)

    print_section("XOR-encoded strings Analysis")
    print("[INFO] Checking for XOR-encoded strings...")
    brute_force_xor_strings(args.file)

    print_section("Entropy Visualization")
    print("[INFO] Generating entropy visualization...")
    plot_entropy(args.file)

    print("\n[INFO] Analysis completed!")

if __name__ == "__main__":
    main()
