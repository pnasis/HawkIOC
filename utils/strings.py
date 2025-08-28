# -*- coding: utf-8 -*-
"""
String extraction helpers (ASCII & UTF-16LE).
"""

import re
import string


def extract_strings(file_path, min_length=4):
    """Extract ASCII and UTF-16LE strings from a file."""
    with open(file_path, "rb") as fobj:
        data = fobj.read()

    # ASCII strings
    ascii_strings = re.findall(
        f"[{re.escape(string.printable)}]{{{min_length},}}",
        data.decode(errors="ignore"),
    )

    # Unicode (UTF-16LE) strings pattern: printable + 0x00
    unicode_strings = re.findall(
        r"(?:[\x20-\x7E]\x00){%d,}" % min_length,
        data.decode("utf-16le", errors="ignore"),
    )

    return ascii_strings + unicode_strings


def save_strings_to_file(strings, file_path):
    """Save extracted strings to '<file>_strings.txt'."""
    output_file = f"{file_path}_strings.txt"
    with open(output_file, "w", encoding="utf-8") as fobj:
        for line in strings:
            fobj.write(line + "\n")
    return output_file
