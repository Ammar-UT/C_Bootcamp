#!/usr/bin/env python3
"""
Cyber Bootcamp - Python for Cybersecurity
Assignment 7: Automated Log Analyzer (أداة تحليل السجلات الأمنية المؤتمتة)

Description:
A SOC-oriented Python script designed to automatically parse web server log files line by line,
apply compiled regular expressions (Regex) to detect malicious activities (such as SQL Injection,
Path Traversal, Cross-Site Scripting, and Command Injection), and print detailed security alerts
with a final analysis summary report.
"""

import os
import re
import sys

# =============================================================================
# Step 1: Define Attack Signatures (Matching Patterns)
# Using re.compile with re.IGNORECASE to ignore uppercase/lowercase differences
# =============================================================================
ATTACK_PATTERNS = {
    "SQL Injection (SQLi)": re.compile(
        r"(\bunion\s+select\b|\bselect\s+.*\s+from\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|--|\bwaitfor\s+delay\b|\bsleep\(\d+\))",
        re.IGNORECASE,
    ),
    "Path Traversal / LFI": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/windows/system32|win\.ini|boot\.ini)",
        re.IGNORECASE,
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|<img.*?src=)",
        re.IGNORECASE,
    ),
    "Command Injection (RCE)": re.compile(
        r"(;|\||&&)\s*(cat\s+/etc|whoami|id|/bin/sh|/bin/bash|powershell|cmd\.exe)",
        re.IGNORECASE,
    ),
}

# Regular expression pattern to identify client IP address in standard web server logs
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip(line: str) -> str:
    """
    Helper function to extract IPv4 address from a log entry line.
    Returns 'Unknown IP' if no valid IP address is found.
    """
    match = re.search(IP_REGEX, line)
    return match.group(0) if match else "Unknown IP"


def analyze_log_file(file_path: str):
    """
    Reads the given log file line by line using 'with open()', applies regex patterns
    to identify attacks, and prints custom alerts and an overall summary report.
    """
    total_lines = 0
    total_attacks = 0
    # Dictionary to keep track of detection count per attack category
    attack_counts = {attack_name: 0 for attack_name in ATTACK_PATTERNS}

    # Step 2: Read the log file line by line using 'with open()' block
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            print("=" * 65)
            print("       AUTOMATED LOG ANALYZER - SOC SECURITY REPORT")
            print(f"       Analyzing: {file_path}")
            print("=" * 65)

            for line_number, raw_line in enumerate(file, start=1):
                total_lines += 1
                line = raw_line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Extract client IP address for alert context
                attacker_ip = extract_ip(line)

                # Step 3: Iterate through patterns and apply regex search to the line
                for attack_name, pattern in ATTACK_PATTERNS.items():
                    # Direct search inside conditional statement using re.search()
                    if re.search(pattern, line):
                        total_attacks += 1
                        attack_counts[attack_name] += 1

                        # Step 4: Print custom security alert with attack type, line number, and attacker IP
                        print(f"\n[!] SECURITY ALERT: {attack_name} Detected!")
                        print(f"    ├── Line Number : {line_number}")
                        print(f"    ├── Attacker IP : {attacker_ip}")
                        print(f"    └── Log Entry   : {line}")

    except FileNotFoundError:
        print(f"[-] Error: Log file '{file_path}' not found.")
        return
    except PermissionError:
        print(f"[-] Error: Permission denied when attempting to read '{file_path}'.")
        return

    # Step 5: Display overall summary of detected attacks and their types
    print("\n" + "=" * 65)
    print("                         SUMMARY REPORT")
    print("=" * 65)
    print(f" Total Lines Analyzed : {total_lines}")
    print(f" Total Attacks Found  : {total_attacks}")
    print("-" * 65)
    print(" Attacks Breakdown by Type:")
    for attack_name, count in attack_counts.items():
        print(f"   - {attack_name:<28} : {count}")
    print("=" * 65)

    if total_attacks == 0:
        print("[+] Scan Completed: No suspicious activities detected in the logs.")
    else:
        print(f"[!] Scan Completed: {total_attacks} threat(s) detected. Investigation required.")


def main():
    """
    Script entry point. Accepts the log file path via command-line argument
    or prompts the user interactively if no argument is provided.
    """
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-h", "--help"):
            print("Usage: python3 AutomatedLogAnalyzer.py <path_to_log_file>")
            sys.exit(0)
        log_file_path = sys.argv[1]
    else:
        try:
            log_file_path = input("Enter path to log file (e.g. access.log): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nScan aborted by user.")
            sys.exit(0)

        if not log_file_path:
            log_file_path = "access.log"

    analyze_log_file(log_file_path)


if __name__ == "__main__":
    main()
