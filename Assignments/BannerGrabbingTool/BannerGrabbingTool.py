#!/usr/bin/env python3
"""
=============================================================================
Assignment: Assignment 6 - Banner Grabbing Tool
            (التكليف السادس: أداة جلب بصمات الخدمات والخدمات المتفاعلة)
Track:      Cybersecurity Programming Path (Python)
Description:
    A clean, modular, and professional Python tool for active reconnaissance.
    It establishes TCP connections to open ports and retrieves service
    banners to identify running services, server software, and versions
    (e.g., SSH, FTP, HTTP, SMTP). It handles both immediate-banner services
    and interactive services requiring initial request probes (such as HTTP).
=============================================================================
"""

import socket
import sys
import argparse
from typing import Optional, Tuple, List

# Standard HTTP ports that typically require an active HTTP probe
HTTP_PORTS = {80, 8080, 8000, 8081, 8888}

# Default well-known ports to inspect during reconnaissance
DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 8080]


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Tuple[Optional[str], Optional[str]]:
    """
    Connect to a target host on a specific TCP port and retrieve the service banner.

    Args:
        host (str): Target IP address or hostname.
        port (int): Target TCP port number.
        timeout (float): Connection and socket read timeout in seconds.

    Returns:
        Tuple[Optional[str], Optional[str]]:
            (banner_summary, error_message)
            - If successful: (banner_summary, None)
            - If failed or no banner: (None, error_message)
    """
    client_socket = None
    try:
        # Step 1: Create a standard IPv4 TCP stream socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Step 2: Set the socket timeout to handle unresponsive ports smoothly
        client_socket.settimeout(timeout)

        # Step 3: Establish connection to the target service
        client_socket.connect((host, port))

        raw_data = b""

        # Step 4: Handle interactive services vs. immediate-banner services
        if port in HTTP_PORTS:
            # Web servers (HTTP) require an initial client request before sending a banner.
            # We send a standard HTTP HEAD request to minimize bandwidth while fetching headers.
            http_request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BannerGrabber/1.0\r\nConnection: close\r\n\r\n"
            client_socket.sendall(http_request.encode('utf-8'))
            raw_data = client_socket.recv(1024)
        else:
            # Immediate services (like SSH, FTP, SMTP) transmit a welcome banner upon connection.
            try:
                raw_data = client_socket.recv(1024)
            except socket.timeout:
                # If no immediate banner was sent, send a generic probe (CRLF) for interactive services
                probe = b"\r\n"
                client_socket.sendall(probe)
                raw_data = client_socket.recv(1024)

        # Step 5: Check if data was received
        if not raw_data:
            return None, "Connection established, but no banner was returned."

        # Step 6: Decode returned bytes safely using utf-8 with error ignoring to avoid crashes
        decoded_banner = raw_data.decode('utf-8', errors='ignore').strip()

        if not decoded_banner:
            return None, "Empty banner received."

        # Step 7: Filter and extract the primary identification line
        lines = decoded_banner.splitlines()
        primary_line = lines[0].strip() if lines else decoded_banner

        # For HTTP responses, also attempt to extract the specific 'Server:' header if present
        server_header = None
        for line in lines:
            if line.lower().startswith("server:"):
                server_header = line.strip()
                break

        if server_header:
            summary = f"{primary_line} | {server_header}"
        else:
            summary = primary_line

        return summary, None

    except socket.timeout:
        return None, f"Timeout (No response within {timeout}s)."
    except ConnectionRefusedError:
        return None, "Connection refused (Port closed or filtered)."
    except socket.gaierror:
        return None, f"Host resolution failed for '{host}'."
    except socket.error as sock_err:
        return None, f"Socket error: {sock_err}"
    except Exception as exc:
        return None, f"Unexpected error: {exc}"
    finally:
        # Step 8: Ensure socket resources are always properly closed
        if client_socket:
            try:
                client_socket.close()
            except Exception:
                pass


def parse_ports(port_arg: str) -> List[int]:
    """
    Parse a comma-separated list of ports or port ranges into a list of integers.
    Example inputs: '21,22,80' or '20-25,80,8080'
    """
    ports = set()
    for part in port_arg.split(','):
        part = part.strip()
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            start, end = int(start_str), int(end_str)
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))


def run_banner_grabber(target_host: str, ports: List[int], timeout: float = 2.0) -> None:
    """
    Scan the target host across specified ports and print discovered banners.
    """
    print("=" * 70)
    print("         BANNER GRABBING & SERVICE RECONNAISSANCE TOOL         ")
    print("=" * 70)
    print(f"[*] Target Host : {target_host}")
    print(f"[*] Target Ports: {', '.join(str(p) for p in ports)}")
    print(f"[*] Timeout     : {timeout} seconds")
    print("-" * 70)
    print(f"{'PORT':<10} {'STATUS':<15} {'BANNER / SERVICE DETAILS'}")
    print("-" * 70)

    banners_found = 0

    for port in ports:
        banner, error = grab_banner(target_host, port, timeout=timeout)
        if banner:
            print(f"{port:<10} {'[OPEN/BANNER]':<15} {banner}")
            banners_found += 1
        else:
            print(f"{port:<10} {'[NO BANNER]':<15} {error}")

    print("-" * 70)
    print(f"[*] Scan completed. {banners_found} banner(s) identified across {len(ports)} port(s).")
    print("=" * 70)


def main() -> None:
    """
    Main entry point for command-line execution.
    """
    parser = argparse.ArgumentParser(
        description="Banner Grabbing Tool - Cybersecurity Active Reconnaissance Utility",
        epilog="Example: python3 BannerGrabbingTool.py 127.0.0.1 -p 21,22,80,8080 -t 2.0"
    )
    parser.add_argument(
        "host",
        nargs="?",
        default="127.0.0.1",
        help="Target IP address or domain (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default=None,
        help="Target ports (e.g., '21,22,80,8080' or '20-25,80'). Defaults to standard ports."
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Socket timeout in seconds (default: 2.0)"
    )

    args = parser.parse_args()

    if args.ports:
        try:
            target_ports = parse_ports(args.ports)
        except ValueError:
            print(f"[!] Error: Invalid port format '{args.ports}'. Use e.g., '21,22,80' or '20-25'.")
            sys.exit(1)
    else:
        target_ports = DEFAULT_PORTS

    run_banner_grabber(args.host, target_ports, args.timeout)


if __name__ == "__main__":
    main()

