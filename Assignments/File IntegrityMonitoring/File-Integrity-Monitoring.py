#!/usr/bin/env python3
"""
=============================================================================
Assignment: Assignment 9 - File Integrity Monitoring (FIM)
            (التكليف التاسع: أداة مراقبة سلامة الملفات)
Course:     Cyber Security Programming Track (Python)
Description:
    A professional, lightweight File Integrity Monitor (FIM) used in Incident
    Response and Security Operations. It monitors sensitive system files for
    unauthorized alterations by establishing a cryptographic baseline (SHA-256)
    and periodically verifying the file's hash against that baseline.
    
Key Requirements Implemented:
    1. Efficient SHA-256 hash calculation using binary read ('rb') in chunks.
    2. Baseline hash generation upon initialization.
    3. Continuous monitoring loop (while True) with regulated intervals (time.sleep).
    4. Instant comparison between the current hash and stored baseline.
    5. Immediate dispatch of critical security alerts (Critical Alert) upon tampering.
    6. Resilient error handling (file removal, permission issues, user interrupt).
=============================================================================
"""

import hashlib
import os
import sys
import time
from datetime import datetime

# Default interval between integrity checks (in seconds)
DEFAULT_CHECK_INTERVAL = 3

# Buffer size for chunked binary reading (4 KB per chunk for high efficiency)
BUFFER_SIZE = 4096


def get_current_timestamp() -> str:
    """
    Returns the current date and time formatted for security logging.
    
    Returns:
        str: Timestamp string in 'YYYY-MM-DD HH:MM:SS' format.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def calculate_sha256(file_path: str, chunk_size: int = BUFFER_SIZE) -> str:
    """
    Calculates the SHA-256 cryptographic hash of a specified file.
    
    To ensure high performance and prevent excessive memory usage with large files,
    the file is opened in binary mode ('rb') and ingested in fixed-size chunks.

    Args:
        file_path (str): The path to the file to be hashed.
        chunk_size (int): Number of bytes to read per iteration (default: 4096).

    Returns:
        str: The 64-character hexadecimal SHA-256 digest of the file.

    Raises:
        FileNotFoundError: If the target file does not exist.
        PermissionError: If read permissions are denied.
        OSError: For other operating system-level I/O errors.
    """
    # Initialize the SHA-256 hashing object from hashlib
    sha256_hasher = hashlib.sha256()

    # Open the file in binary read mode ('rb') for raw byte stream processing
    with open(file_path, "rb") as target_file:
        # Read the file in sequential chunks until reaching the end of the file (EOF)
        while True:
            chunk = target_file.read(chunk_size)
            if not chunk:
                break
            sha256_hasher.update(chunk)

    # Return the computed digest as a lowercase hexadecimal string
    return sha256_hasher.hexdigest()


def monitor_file_integrity(file_path: str, interval: int = DEFAULT_CHECK_INTERVAL) -> None:
    """
    Monitors a file continuously for integrity violations.
    
    Workflow:
      1. Validates the existence and accessibility of the target file.
      2. Computes and records the initial Baseline Hash.
      3. Enters an infinite monitoring loop (while True):
         - Pauses for `interval` seconds via time.sleep() to conserve CPU cycles.
         - Recalculates the file's current SHA-256 digest.
         - Compares the current hash to the baseline.
         - Triggers a Critical Security Alert if a discrepancy is detected.
         - Gracefully handles file deletion or permission errors during runtime.

    Args:
        file_path (str): The target file path to monitor.
        interval (int): Delay in seconds between consecutive integrity checks.
    """
    # Step 1: Ensure the target file exists before starting the monitor
    if not os.path.exists(file_path):
        print(f"[-] Error: Target file '{file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(file_path):
        print(f"[-] Error: '{file_path}' is a directory, not a regular file.", file=sys.stderr)
        sys.exit(1)

    print("=" * 75)
    print("       FILE INTEGRITY MONITORING (FIM) - INCIDENT RESPONSE TOOL")
    print("=" * 75)
    print(f"[*] Target Monitored File : {os.path.abspath(file_path)}")
    print(f"[*] Check Interval        : Every {interval} second(s)")
    print(f"[*] Started At            : {get_current_timestamp()}")

    # Step 2: Establish the initial Baseline Hash
    try:
        baseline_hash = calculate_sha256(file_path)
    except PermissionError:
        print(f"[-] Error: Permission denied when reading '{file_path}'.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[-] Error calculating initial baseline hash: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Initial Baseline Hash : {baseline_hash}")
    print("[*] Status                : Monitoring actively... Press Ctrl+C to stop.")
    print("=" * 75)

    alert_counter = 0

    # Step 3: Continuous Monitoring Loop (while True)
    try:
        while True:
            # Regulate polling frequency to prevent high CPU utilization
            time.sleep(interval)

            # Check if the file still exists on disk
            if not os.path.exists(file_path):
                alert_counter += 1
                timestamp = get_current_timestamp()
                print("\n" + "!" * 75)
                print(f" [CRITICAL ALERT #{alert_counter}] FILE DELETION / DISAPPEARANCE DETECTED!")
                print("!" * 75)
                print(f" Timestamp     : {timestamp}")
                print(f" Monitored File: {os.path.abspath(file_path)}")
                print(" Event Details : Target file was removed or unlinked from the filesystem!")
                print("!" * 75 + "\n")
                continue

            try:
                # Recalculate the current SHA-256 hash of the file
                current_hash = calculate_sha256(file_path)
            except PermissionError:
                timestamp = get_current_timestamp()
                print(f"[!] [{timestamp}] Warning: Permission denied while accessing '{file_path}'.")
                continue
            except Exception as exc:
                timestamp = get_current_timestamp()
                print(f"[!] [{timestamp}] Warning: Error reading file: {exc}")
                continue

            # Step 4: Compare current hash with baseline
            if current_hash != baseline_hash:
                # Step 5: Trigger Critical Security Alert
                alert_counter += 1
                timestamp = get_current_timestamp()

                print("\n" + "!" * 75)
                print(f" [CRITICAL ALERT #{alert_counter}] UNAUTHORIZED FILE MODIFICATION DETECTED!")
                print("!" * 75)
                print(f" Timestamp     : {timestamp}")
                print(f" Monitored File: {os.path.abspath(file_path)}")
                print(f" Baseline Hash : {baseline_hash}")
                print(f" Current Hash  : {current_hash}")
                print(" Status        : Integrity compromised! Content mismatch identified.")
                print("!" * 75 + "\n")

                # Update the baseline to the new hash to detect subsequent tampering
                baseline_hash = current_hash

    except KeyboardInterrupt:
        # Gracefully handle manual termination (Ctrl+C)
        print("\n\n" + "-" * 75)
        print(f"[*] [{get_current_timestamp()}] Monitoring stopped by administrator.")
        print(f"[*] Total Critical Alerts Recorded: {alert_counter}")
        print("-" * 75)
        sys.exit(0)


def main() -> None:
    """
    Main entry point for the File Integrity Monitoring script.
    Accepts target file path via CLI argument or prompts interactively.
    """
    target_file = None
    check_interval = DEFAULT_CHECK_INTERVAL

    # Support command-line arguments: python3 File-Integrity-Monitoring.py [file] [interval]
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-h", "--help"):
            print("Usage: python3 File-Integrity-Monitoring.py [target_file] [interval_seconds]")
            print("\nArguments:")
            print("  target_file       Path to the file to monitor (required if passed via CLI)")
            print(f"  interval_seconds  Check frequency in seconds (optional, default: {DEFAULT_CHECK_INTERVAL})")
            sys.exit(0)

        target_file = sys.argv[1]

        if len(sys.argv) > 2:
            try:
                check_interval = int(sys.argv[2])
                if check_interval <= 0:
                    raise ValueError
            except ValueError:
                print(f"[-] Invalid interval '{sys.argv[2]}'. Using default ({DEFAULT_CHECK_INTERVAL}s).")
                check_interval = DEFAULT_CHECK_INTERVAL

    # If no file was supplied as CLI argument, prompt the user interactively
    if not target_file:
        try:
            target_file = input("Enter path to the file you want to monitor: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Operation aborted by user.")
            sys.exit(0)

    if not target_file:
        print("[-] Error: No file specified. Exiting.", file=sys.stderr)
        sys.exit(1)

    # Start the monitoring service
    monitor_file_integrity(target_file, check_interval)


if __name__ == "__main__":
    main()

