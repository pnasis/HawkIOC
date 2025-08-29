# -*- coding: utf-8 -*-
"""
PE file analyzer.
"""

import hashlib
import os
import subprocess

import pefile
from core.base import FileAnalyzer
from utils.common import (
    print_section,
    hash_md5_bytes,
    hash_sha256_bytes,
)
from utils.entropy import analyze_entropy, plot_entropy
from utils.file_info import get_file_type


SUSPICIOUS_APIS = [
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "RegOpenKeyExA", "RegSetValueExA", "RegQueryValueExA",
    "CreateFileA", "InternetReadFile", "CloseHandle",
    "InternetCloseHandle", "InternetOpenUrlA", "GetComputerNameA",
    "CreateProcessA",
]


class PEAnalyzer(FileAnalyzer):
    """Analyzer for PE (Portable Executable) files."""

    def analyze(self):
        """Run the full PE analysis pipeline."""
        imphash, section_hashes, pe = self._get_pe_hashes()
        if not pe:
            print("[ERROR] Not a valid PE file.")
            return

        print_section("PE File Analysis")
        if imphash:
            print(f"[INFO] IMPHASH: {imphash}")
        for section, hashes in (section_hashes or {}).items():
            print(
                f"[INFO] Section: {section}, "
                f"MD5: {hashes['MD5']}, SHA256: {hashes['SHA256']}"
            )

        packed = analyze_entropy(self.file_path, pe)
        print_section("Entropy Visualization")
        print("[INFO] Generating entropy visualization...")
        plot_entropy(self.file_path, pe)

        print_section("PE Resources")
        print("[INFO] Extracting PE Resources...")
        self._extract_resources()

        print_section("Import Functions")
        print("[INFO] Extracting Import Functions...")
        self._extract_imports()

        print_section("Suspicious API Calls")
        print("[INFO] Checking for Suspicious API Calls...")
        self._detect_suspicious_imports()

        if packed and self._is_upx_packed(pe):
            print_section("UPX Detection & Unpacking")
            print("[INFO] UPX packer detected!")
            unpacked = self._unpack_upx()
            if unpacked:
                # Re-analyze unpacked file (basic info + entropy) for brevity
                print(f"[INFO] Re-analyzing unpacked file: {unpacked}")
                ftype, _ = get_file_type(unpacked)
                if ftype and "pe32" in ftype.lower():
                    # Basic re-run of entropy/sections
                    imphash2, section_hashes2, pe2 = self._get_pe_hashes(
                        unpacked
                    )
                    print_section("Unpacked PE Analysis")
                    print(f"[INFO] IMPHASH: {imphash2}")
                    for section, hashes in (section_hashes2 or {}).items():
                        print(
                            f"[INFO] Section: {section}, "
                            f"MD5: {hashes['MD5']}, "
                            f"SHA256: {hashes['SHA256']}"
                        )
                    analyze_entropy(unpacked, pe2)

    def _get_pe_hashes(self, path=None):
        """Return imphash and section hashes for a PE file."""
        target = path or self.file_path
        try:
            pe = pefile.PE(target)
            imphash = pe.get_imphash()
            section_hashes = {}
            for section in pe.sections:
                data = section.get_data()
                md5_section = hashlib.md5(data).hexdigest()
                sha256_section = hashlib.sha256(data).hexdigest()
                name = section.Name.decode(errors="ignore").strip("\x00").strip()
                section_hashes[name] = {
                    "MD5": md5_section,
                    "SHA256": sha256_section,
                }
            return imphash, section_hashes, pe
        except pefile.PEFormatError:
            return None, None, None

    def _extract_resources(self):
        """List resources in the PE file."""
        try:
            pe = pefile.PE(self.file_path)
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    print(f"[INFO] Found resource type: {res.struct.Id}")
            else:
                print("[INFO] No resources found.")
        except pefile.PEFormatError:
            print("[ERROR] Invalid PE for resource extraction.")

    def _extract_imports(self):
        """Print imported functions grouped by DLL."""
        try:
            pe = pefile.PE(self.file_path)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                print("[INFO] Imported Functions:")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode(errors="ignore")
                    print(f"  - DLL: {dll_name}")
                    for imp in entry.imports:
                        name = (
                            imp.name.decode(errors="ignore")
                            if imp.name else "Ordinal"
                        )
                        print(f"    * {name}")
            else:
                print("[INFO] No imports found.")
        except pefile.PEFormatError:
            print("[ERROR] Invalid PE for import parsing.")

    def _detect_suspicious_imports(self):
        """Heuristically flag suspicious imports."""
        try:
            pe = pefile.PE(self.file_path)
            if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                return
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    name = imp.name.decode(errors="ignore")
                    if any(api in name for api in SUSPICIOUS_APIS):
                        print(f"[WARNING] Suspicious API Found: {name}")
        except pefile.PEFormatError:
            print("[ERROR] Invalid PE for suspicious import detection.")

    def _is_upx_packed(self, pe):
        """Detect UPX by section names."""
        return any(b"UPX" in sec.Name for sec in pe.sections)

    def _unpack_upx(self):
        """Attempt to unpack a UPX-packed file."""
        base_name = os.path.basename(self.file_path)
        stem, ext = os.path.splitext(base_name)
        out_name = f"{stem}_unpacked{ext}"
        try:
            result = subprocess.run(
                ["upx", "-d", "-o", out_name, self.file_path],
                capture_output=True,
                text=True,
            )
            if "Unpacked" in result.stdout:
                print(f"[INFO] Successfully unpacked: {out_name}")
                return out_name
            print("[ERROR] UPX unpacking failed!")
            if result.stderr:
                print(result.stderr)
            return None
        except FileNotFoundError:
            print(
                "[ERROR] UPX not found. Please install UPX to enable unpacking."
            )
            return None
