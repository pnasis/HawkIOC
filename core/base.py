# -*- coding: utf-8 -*-
"""
Abstract base classes and shared analyzer behavior.
"""

from abc import ABC, abstractmethod

from utils.common import print_section


class FileAnalyzer(ABC):
    """Abstract base class for file analyzers."""

    def __init__(self, file_path, file_type=None):
        self.file_path = file_path
        self.file_type = file_type

    @abstractmethod
    def analyze(self):
        """Run analyzer specific to file type."""
        raise NotImplementedError

    # Optional shared utilities could be added here
    @staticmethod
    def section(title):
        """Convenience wrapper for section printing."""
        print_section(title)
