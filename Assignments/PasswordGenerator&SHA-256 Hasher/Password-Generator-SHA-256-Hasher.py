#!/usr/bin/env python3
"""
=============================================================================
Assignment: Assignment 8 - Password Generator & SHA-256 Hasher
            (التكليف الثامن: أداة مولد كلمات السر وحساب التجزئة)
Course:     Cyber Security Programming Track (Python)
Description:
    A professional, cryptographically sound command-line utility providing
    two essential security functions:
    1. Cryptographically Secure Password Generation:
       Generates high-entropy passwords incorporating uppercase letters,
       lowercase letters, numerical digits, and special punctuation symbols
       using Python's 'secrets' module (CSPRNG).
    2. Cryptographic Hash Calculation (SHA-256):
       Calculates the standard SHA-256 cryptographic digest of plain text/passwords
       using Python's 'hashlib' module, displaying the result in hexadecimal.
    3. Educational Demonstration of Password Hashing Principles:
       Illustrates one-way functions, fixed-length digests, and the avalanche
       effect in cryptographic security.
=============================================================================
"""

import argparse
import hashlib
import secrets
import string
import sys
from typing import Tuple


# =============================================================================
# Core Security Functions
# =============================================================================

def generate_password(length: int = 16) -> str:
    """
    Generates a cryptographically secure random password meeting strict complexity rules.

    The password is guaranteed to contain:
      - At least one uppercase letter (A-Z)
      - At least one lowercase letter (a-z)
      - At least one digit (0-9)
      - At least one special symbol / punctuation character

    Security Note:
      Uses the 'secrets' module, which relies on the operating system's
      cryptographically secure pseudo-random number generator (CSPRNG)
      (e.g., /dev/urandom on Unix/Linux or CryptGenRandom/BCrypt on Windows).
      This prevents prediction attacks common with the standard 'random' module.

    Args:
        length (int): Total length of the password (minimum recommended: 8, default: 16).

    Returns:
        str: The generated secure password.

    Raises:
        ValueError: If length is less than 4 (minimum needed for all 4 character classes).
    """
    # Enforce minimum length to ensure all character classes can be included
    if length < 4:
        raise ValueError("Password length must be at least 4 characters to satisfy complexity rules.")

    # Step 1: Define individual character classes
    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digit_chars = string.digits
    punctuation_chars = string.punctuation

    # Step 2: Combine character sets to create the total character pool
    # Equivalent to: string.ascii_letters + string.digits + string.punctuation
    all_chars = string.ascii_letters + digit_chars + punctuation_chars

    # Step 3: Guarantee at least one character from each mandatory class
    password_chars = [
        secrets.choice(lowercase_chars),
        secrets.choice(uppercase_chars),
        secrets.choice(digit_chars),
        secrets.choice(punctuation_chars),
    ]

    # Step 4: Fill the remaining length using cryptographically secure random selection
    remaining_length = length - len(password_chars)
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(all_chars))

    # Step 5: Securely shuffle the password characters in-place
    # secrets.SystemRandom() provides a CSPRNG-backed Fisher-Yates shuffle
    secrets.SystemRandom().shuffle(password_chars)

    # Return the assembled password as a string
    return "".join(password_chars)


def calculate_sha256(text: str) -> str:
    """
    Calculates the cryptographic SHA-256 hash of a given text string.

    Cryptographic Steps:
      1. Encodes the input string to raw bytes using UTF-8 encoding.
      2. Ingests bytes into the SHA-256 hashing algorithm via hashlib.sha256().
      3. Produces a fixed-length 256-bit (32-byte) digest.
      4. Formats and returns the digest as a 64-character hexadecimal string.

    Args:
        text (str): The plain text or password to hash.

    Returns:
        str: The 64-character hexadecimal SHA-256 hash digest.
    """
    # Step 1: Encode the text string to bytes using UTF-8 encoding
    encoded_bytes = text.encode("utf-8")

    # Step 2: Initialize SHA-256 hasher and pass the encoded bytes
    sha256_hasher = hashlib.sha256(encoded_bytes)

    # Step 3: Extract and return the hexadecimal representation
    return sha256_hasher.hexdigest()


def generate_and_hash_password(length: int = 16) -> Tuple[str, str]:
    """
    Convenience function that generates a secure password and immediately
    computes its corresponding SHA-256 hexadecimal hash.

    Args:
        length (int): Length of the password to generate.

    Returns:
        Tuple[str, str]: (generated_password, sha256_hex_digest)
    """
    password = generate_password(length)
    hash_value = calculate_sha256(password)
    return password, hash_value


# =============================================================================
# Educational Concept Explanation
# =============================================================================

def display_security_explanation() -> None:
    """
    Prints an educational overview explaining why cryptographic hashing
    is vital for secure password storage and authentication.
    """
    print("-" * 75)
    print("🔒 [CYBERSECURITY INSIGHT: WHY HASH PASSWORDS?]")
    print("-" * 75)
    print(" 1. One-Way Property (Pre-Image Resistance):")
    print("    A cryptographic hash is a one-way mathematical function. It is easy")
    print("    to compute H(P) from password P, but computationally infeasible to")
    print("    reverse H back to P. Systems store H(P) so that even if the database")
    print("    is breached, plain-text credentials remain protected.")
    print("\n 2. Fixed Digest Size (256 Bits / 64 Hex Characters):")
    print("    Regardless of whether the input is 4 characters or 10,000 characters,")
    print("    SHA-256 always outputs exactly 256 bits (64 hexadecimal characters).")
    print("\n 3. Avalanche Effect (Diffusion):")
    print("    A minute modification to the input (even a single bit or character)")
    print("    drastically alters the resulting hash, making pattern analysis impossible.")
    print("\n 4. Salting (Best Practice for Real-World Systems):")
    print("    In production authentication systems, a unique random 'salt' is appended")
    print("    to each password before hashing (or slow key-derivation functions like")
    print("    Argon2id or bcrypt are used) to prevent precomputed Rainbow Table attacks.")
    print("-" * 75)


def demonstrate_avalanche_effect() -> None:
    """
    Demonstrates the cryptographic Avalanche Effect by comparing two
    almost identical inputs and highlighting how their SHA-256 hashes differ.
    """
    text1 = "CyberBootcamp2026!"
    text2 = "CyberBootcamp2026?"

    hash1 = calculate_sha256(text1)
    hash2 = calculate_sha256(text2)

    print("\n" + "=" * 75)
    print("       DEMONSTRATION: THE AVALANCHE EFFECT IN SHA-256")
    print("=" * 75)
    print(f" Input 1: '{text1}'")
    print(f" SHA-256: {hash1}")
    print("-" * 75)
    print(f" Input 2: '{text2}' (Only 1 character changed: '!' -> '?')")
    print(f" SHA-256: {hash2}")
    print("-" * 75)

    # Calculate differing hex characters count
    diff_chars = sum(1 for c1, c2 in zip(hash1, hash2) if c1 != c2)
    print(f" [*] Result: {diff_chars} out of 64 characters changed ({diff_chars/64*100:.1f}%).")
    print("=" * 75)


# =============================================================================
# Command-Line Interface & Application Entry Point
# =============================================================================

def print_banner() -> None:
    """Prints the application banner."""
    print("=" * 75)
    print("     PASSWORD GENERATOR & SHA-256 HASHER (مولد كلمات السر وحساب التجزئة)")
    print("         Track: Cyber Security Programming (Python) - Assignment 8")
    print("=" * 75)


def run_interactive_mode() -> None:
    """
    Runs an interactive terminal session allowing the user to generate
    passwords, hash custom strings, and view cryptographic explanations.
    """
    print_banner()

    try:
        # Step 1: Prompt for password length
        user_input = input("\nEnter desired password length [Default: 16, Min: 8]: ").strip()
        if not user_input:
            password_length = 16
        else:
            password_length = int(user_input)
            if password_length < 8:
                print("[!] Warning: Passwords shorter than 8 characters are vulnerable.")
                print("[*] Automatically adjusting length to the secure minimum of 8.")
                password_length = 8

        # Step 2: Generate secure password and compute its SHA-256 hash
        pwd, pwd_hash = generate_and_hash_password(password_length)

        # Step 3: Display results
        print("\n" + "-" * 75)
        print("🔑 GENERATED CREDENTIALS & CRYPTOGRAPHIC HASH:")
        print("-" * 75)
        print(f" Password Length : {len(pwd)} characters")
        print(f" Random Password : {pwd}")
        print(f" SHA-256 (Hex)   : {pwd_hash}")
        print("-" * 75)

        # Step 4: Educational overview
        display_security_explanation()

        # Step 5: Optional custom text hashing
        custom_input = input("\nWould you like to calculate SHA-256 for custom text? (y/N): ").strip().lower()
        if custom_input == "y":
            custom_text = input("Enter text to hash: ")
            custom_hash = calculate_sha256(custom_text)
            print("-" * 75)
            print(f" Original Text : {custom_text}")
            print(f" SHA-256 (Hex) : {custom_hash}")
            print("-" * 75)

    except ValueError:
        print("[-] Error: Please enter a valid positive integer for password length.")
    except (KeyboardInterrupt, EOFError):
        print("\n\n[*] Operation cancelled by user. Exiting safely.")
        sys.exit(0)


def main() -> None:
    """
    Main entry point supporting both command-line arguments and interactive mode.
    """
    parser = argparse.ArgumentParser(
        description="Password Generator & SHA-256 Hasher - Cybersecurity Cryptographic Tool",
        epilog="Example: python3 Password-Generator-SHA-256-Hasher.py -l 20 --explain"
    )
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=None,
        help="Length of the random password to generate (minimum: 4, recommended: >= 12)"
    )
    parser.add_argument(
        "-t", "--text",
        type=str,
        default=None,
        help="Directly calculate the SHA-256 hash of the specified plain-text string"
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        help="Number of passwords to generate (default: 1)"
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print an educational explanation of password hashing and cybersecurity concepts"
    )
    parser.add_argument(
        "--avalanche",
        action="store_true",
        help="Demonstrate the cryptographic avalanche effect using sample strings"
    )

    args = parser.parse_args()

    # Handle avalanche demo flag
    if args.avalanche:
        demonstrate_avalanche_effect()
        return

    # Handle direct text hashing flag
    if args.text is not None:
        text_hash = calculate_sha256(args.text)
        print(f"Text   : {args.text}")
        print(f"SHA-256: {text_hash}")
        if args.explain:
            display_security_explanation()
        return

    # If length was specified on CLI, run in non-interactive batch mode
    if args.length is not None:
        try:
            target_length = max(4, args.length)
            for i in range(args.count):
                pwd, hsh = generate_and_hash_password(target_length)
                if args.count == 1:
                    print(f"Password : {pwd}")
                    print(f"SHA-256  : {hsh}")
                else:
                    print(f"[{i + 1}] Password: {pwd} | SHA-256: {hsh}")

            if args.explain:
                display_security_explanation()
        except ValueError as err:
            print(f"[-] Error: {err}", file=sys.stderr)
            sys.exit(1)
        return

    # If no flags provided, run interactive mode
    run_interactive_mode()


if __name__ == "__main__":
    main()

