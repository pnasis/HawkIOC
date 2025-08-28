# -*- coding: utf-8 -*-
"""
Analyzer factory: picks the right analyzer class based on file type.
"""

from core.pe_analyzer import PEAnalyzer
from core.elf_analyzer import ELFAnalyzer
from core.macho_analyzer import MachOAnalyzer


class AnalyzerFactory:
    """Factory to build appropriate analyzer for the file type."""

    @staticmethod
    def create(file_path, file_type_str):
        """
        Create analyzer instance based on magic's file type string.

        Args:
            file_path (str): path to file
            file_type_str (str): magic string (e.g. 'PE32 executable', 'ELF 64-bit', 'Mach-O ...')

        Returns:
            FileAnalyzer | None
        """
        if not file_type_str:
            return None

        lower = file_type_str.lower()

        if "pe32" in lower or "ms-dos" in lower or "portable executable" in lower:
            return PEAnalyzer(file_path, file_type_str)

        if "elf" in lower:
            return ELFAnalyzer(file_path, file_type_str)

        if "mach-o" in lower:
            return MachOAnalyzer(file_path, file_type_str)

        return None
