# -*- coding: utf-8 -*-
"""
Entropy utilities and plotting.
"""

import math
from collections import Counter

import matplotlib.pyplot as plt

from utils.common import xor_decrypt


def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return entropy


def analyze_entropy(file_path, pe=None):
    """
    Analyze file entropy and detect possible packing.
    If pe is provided, also analyze section entropies.
    """
    with open(file_path, "rb") as fobj:
        file_data = fobj.read()
    file_entropy = calculate_entropy(file_data)
    print_section("Entropy Analysis")
    print(f"[INFO] File Entropy: {file_entropy:.4f}")

    packed = False
    if pe:
        print("\n[INFO] PE Section Entropy:")
        for section in pe.sections:
            section_data = section.get_data()
            section_entropy = calculate_entropy(section_data)
            name = section.Name.decode(errors="ignore").strip()
            print(f"    * {name}: {section_entropy:.4f}")
            if section_entropy > 7.0:
                packed = True

    if file_entropy > 7.0 or packed:
        print("\n[WARNING] High entropy detected! The file is likely packed.")
        return True

    print("\n[INFO] Entropy levels suggest the file is not packed.")
    return False


def plot_entropy(file_path, pe=None):
    """
    Simple bar plot of entropy: file and (optional) PE sections.
    """
    with open(file_path, "rb") as fobj:
        file_data = fobj.read()

    entropies = [calculate_entropy(file_data)]
    labels = ["Full File"]

    if pe:
        for section in pe.sections:
            entropies.append(calculate_entropy(section.get_data()))
            labels.append(section.Name.decode(errors="ignore").strip())

    plt.bar(labels, entropies)
    plt.xlabel("Sections")
    plt.ylabel("Entropy")
    plt.title("Entropy Analysis")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


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
            print(
                f"[ALERT] Possible XOR-encoded strings found with key {key}!"
            )


def print_section(title):
    # Local import to avoid circular import; mirrors utils.common.print_section
    print("\n" + "=" * 50)
    print(f"\t\t[{title}]")
    print("=" * 50)
