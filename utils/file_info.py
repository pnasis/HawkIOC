# -*- coding: utf-8 -*-
"""
File information utilities: magic type, magic numbers, hashes, ssdeep.
"""

import hashlib

import magic
import ssdeep


def get_file_type(file_path):
    """
    Return file type string from libmagic and the first 8-byte magic number hex.
    """
    file_magic = magic.Magic()
    file_type = file_magic.from_file(file_path)
    with open(file_path, "rb") as fobj:
        magic_numbers = fobj.read(8).hex().upper()
    return file_type, magic_numbers


def calculate_hashes(file_path):
    """Return MD5 and SHA256 hashes of a file."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as fobj:
        while True:
            chunk = fobj.read(4096)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    return md5_hash.hexdigest(), sha256_hash.hexdigest()


def get_fuzzy_hash(file_path):
    """Return SSDEEP fuzzy hash of a file."""
    return ssdeep.hash_from_file(file_path)
