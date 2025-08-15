# Payload-Generator-Tool


A Python-based command-line tool for generating evasion-ready payloads for web application security testing. It supports Cross-Site Scripting (XSS), SQL Injection (SQLi), and Command Injection payloads with customizable variants, encoding, obfuscation, and output options. Designed for ethical and authorized testing only, this tool is ideal for practicing on platforms like PortSwigger Web Security Academy or TryHackMe.


Features





Modules:





XSS: Variants include reflected, stored, and DOM-based payloads.



SQL Injection: Variants include error-based, union-based, and blind payloads.



Command Injection: Variants include Linux and Windows payloads.



Evasion Techniques:





Encoding: Base64, URL, Hex, Unicode.



Obfuscation: Low (random case, spacing) and High (comments, null bytes).



Output Options: CLI, JSON file, or clipboard.



Integration: Send payloads to Burp Suite Repeater API for advanced testing.



Interface: Interactive CLI menu using Python’s match statement (Python 3.10+).
