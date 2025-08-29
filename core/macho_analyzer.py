# -*- coding: utf-8 -*-
"""
Mach-O file analyzer.
"""

import lief
from core.base import FileAnalyzer
from utils.common import print_section
from utils.entropy import analyze_entropy, plot_entropy


class MachOAnalyzer(FileAnalyzer):
    """Analyzer for Mach-O binaries (macOS)."""

    def analyze(self):
        """Run the Mach-O analysis pipeline."""
        print_section("Mach-O File Analysis")
        binary = lief.parse(self.file_path)
        if not binary:
            print("[ERROR] Failed to parse Mach-O file.")
            return

        print(f"[INFO] Mach-O Type: {binary.header.file_type}")
        try:
            print(f"[INFO] Entry Point: 0x{binary.entrypoint:x}")
        except Exception:
            print("[INFO] Entry Point: <unavailable>")

        print("[INFO] Libraries:")
        for lib in getattr(binary, "libraries", []):
            print(f"  * {lib}")

        print("[INFO] Sections:")
        for section in getattr(binary, "sections", []):
            print(f"  * {section.name} (size: {section.size} bytes)")

        analyze_entropy(self.file_path, None)
        print_section("Entropy Visualization")
        print("[INFO] Generating entropy visualization...")
        plot_entropy(self.file_path, None)
