# -*- coding: utf-8 -*-
"""
Common helper utilities.
"""

import hashlib


def print_section(title):
    """Print section header with separators."""
    print("\n" + "=" * 50)
    print(f"\t\t[{title}]")
    print("=" * 50)


def hash_md5_bytes(data):
    """MD5 for bytes."""
    return hashlib.md5(data).hexdigest()


def hash_sha256_bytes(data):
    """SHA-256 for bytes."""
    return hashlib.sha256(data).hexdigest()


def xor_decrypt(data, key):
    """XOR a byte sequence with a single-byte key."""
    return bytes([b ^ key for b in data])
