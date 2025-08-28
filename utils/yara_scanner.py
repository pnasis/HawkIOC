# -*- coding: utf-8 -*-
"""
YARA integration (external `yara` CLI).
"""

import subprocess


def run_yara(file_path, yara_rule):
    """
    Run YARA rules via subprocess and print results.

    Args:
        file_path (str): target file
        yara_rule (str): path to rule(s)
    """
    try:
        result = subprocess.run(
            ["yara", yara_rule, file_path],
            capture_output=True,
            text=True,
        )
        if result.stdout:
            print("[INFO] YARA Scan Results:\n", result.stdout)
        if result.stderr:
            # Some YARA warnings print to stderr
            print("[YARA] ", result.stderr.strip())
    except FileNotFoundError:
        print("[ERROR] 'yara' CLI not found in PATH.")
