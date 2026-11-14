#!/usr/bin/env python3
"""
Assignment 5: Multithreaded Port Scanner (أداة فحص المنافذ متعددة الخيوط)
Course: Cyber Security Programming Track (Python)

Description:
A fast, multithreaded network port scanner written in Python that utilizes
low-level TCP sockets and the concurrent.futures module to discover open ports
and active services on a specified target IP address efficiently without hanging.
"""

import sys
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor

# Thread-safe lock for printing to the console
print_lock = threading.Lock()

# List to keep track of discovered open ports
open_ports = []


def scan_port(target_ip, port):
    """
    Scans a single TCP port on the target IP address.

    Args:
        target_ip (str): Target IPv4 address.
        port (int): Port number to test.

    Returns:
        int or None: The port number if open, otherwise None.
    """
    # Create a stream socket for IPv4 and TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set timeout to prevent the script from hanging on closed/filtered ports
    s.settimeout(1.0)

    try:
        # connect_ex returns 0 if the connection succeeds (port is open)
        result = s.connect_ex((target_ip, port))

        if result == 0:
            # Attempt to resolve common service name for the port
            try:
                service = socket.getservbyport(port, "tcp")
            except (OSError, socket.error):
                service = "Unknown"

            # Print open port immediately to the console in a thread-safe manner
            with print_lock:
                print(f"[+] Port {port:<5} : OPEN ({service})")
                open_ports.append(port)
            return port

    except (socket.timeout, socket.error, OSError):
        # Ignore socket communication errors on closed or unresponsive ports
        pass
    finally:
        # Ensure the socket is always properly closed to prevent resource leaks
        s.close()

    return None


def main():
    """
    Main function to parse input, orchestrate multithreaded scanning,
    and report summary statistics.
    """
    print("=" * 60)
    print("      Multithreaded Port Scanner - أداة فحص المنافذ      ")
    print("=" * 60)

    # Obtain target host from command-line argument or interactive prompt
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target IP or hostname [default: 127.0.0.1]: ").strip()
        if not target:
            target = "127.0.0.1"

    # Port range configuration (default: 1 to 1024 as specified in the assignment)
    start_port = 1
    end_port = 1024

    if len(sys.argv) > 3:
        try:
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
        except ValueError:
            print("[-] Invalid port range provided. Using default 1-1024.")
            start_port, end_port = 1, 1024

    # Resolve target hostname to an IPv4 address
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{target}'. Exiting.")
        sys.exit(1)
    except socket.error as err:
        print(f"[-] Socket error while resolving target: {err}")
        sys.exit(1)

    print(f"\n[*] Target Host      : {target} ({target_ip})")
    print(f"[*] Port Range       : {start_port} to {end_port}")
    print(f"[*] Concurrent Threads: 50")
    print(f"[*] Scan Started at  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    # Record the start time to calculate total scan duration
    start_time = time.time()

    try:
        # Utilize ThreadPoolExecutor with 50 worker threads to scan concurrently
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Map port range across worker threads
            ports = range(start_port, end_port + 1)
            executor.map(lambda p: scan_port(target_ip, p), ports)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

    # Calculate total elapsed time
    elapsed_time = time.time() - start_time

    # Print summary report
    print("-" * 60)
    print(f"[*] Scan Completed in : {elapsed_time:.2f} seconds")
    print(f"[*] Open Ports Found  : {len(open_ports)}")
    if open_ports:
        print(f"[*] List of Open Ports: {sorted(open_ports)}")
    print("=" * 60)


if __name__ == "__main__":
    main()

