#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: domain.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 16:12:08

import re
import idna

def validate_domain(domain: str) -> dict:
    """
    Validates a domain name including IDN (internationalized domains).

    Args:
        domain (str): The domain name to validate.

    Returns:
        dict: {
            "Domain": str,
            "Valid": bool,
            "Error": str or None,
            "Punycode": str or None
        }
    """
    result = {
        "Domain": domain,
        "Valid": False,
        "Error": None,
        "Punycode": None
    }

    if not isinstance(domain, str) or len(domain) > 253:
        result["Error"] = "Domain must be a string ≤ 253 characters"
        return result

    # Try to encode to Punycode (IDNA)
    try:
        punycode = idna.encode(domain).decode("ascii")
        result["Punycode"] = punycode
    except idna.IDNAError:
        result["Error"] = "Invalid international domain encoding"
        return result

    # Validate using RFC-compliant domain regex
    domain_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
    )

    if not domain_regex.match(punycode):
        result["Error"] = "Domain format invalid"
        return result

    result["Valid"] = True
    return result


if __name__ == "__main__":
    test_domains = [
        "example.com",                  # Valid
        "sub.example.co.uk",           # Valid
        "xn--caf-dma.com",             # Punycode already
        "café.com",                    # IDN
        "-invalid.com",                # Starts with dash
        "toolong-" + "a" * 250 + ".com",  # Exceeds 253 chars
        "no-tld",                      # Missing TLD
        "example.123",                 # Numeric TLD (technically invalid)
        "exa_mple.com",                # Invalid char
        "例子.测试"                    # Chinese IDN
    ]

    print("Domain Validation Test Results:\n")
    for domain in test_domains:
        result = validate_domain(domain)
        status = "✅" if result["Valid"] else "❌"
        reason = f"({result['Error']})" if result["Error"] else ""
        print(f"{status} {domain:35} → Punycode: {result['Punycode'] or '-'} {reason}")

