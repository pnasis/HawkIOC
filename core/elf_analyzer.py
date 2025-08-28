# -*- coding: utf-8 -*-
"""
ELF file analyzer.
"""

from elftools.elf.elffile import ELFFile

from core.base import FileAnalyzer
from utils.common import print_section
from utils.entropy import analyze_entropy


class ELFAnalyzer(FileAnalyzer):
    """Analyzer for ELF binaries."""

    def analyze(self):
        """Run the ELF analysis pipeline."""
        analyze_entropy(self.file_path, None)
        print_section("ELF File Analysis")
        with open(self.file_path, "rb") as fobj:
            elf = ELFFile(fobj)
            print(f"[INFO] ELF Class: {elf.elfclass}-bit")
            print(f"[INFO] Entry Point: 0x{elf.header.e_entry:x}")

            print("[INFO] Sections:")
            for sec in elf.iter_sections():
                print(f"  * {sec.name} (size: {sec.data_size} bytes)")

            print("[INFO] Imports (Dynamic Symbols):")
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym:
                for sym in dynsym.iter_symbols():
                    print(f"  - {sym.name}")
            else:
                print("  - <none>")
