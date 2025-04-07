#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: url.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 16:14:15

from urllib.parse import urlparse
import idna

def validate_url(url: str) -> dict:
    """
    Validates a URL by checking structure and domain format.

    Args:
        url (str): The URL string to validate.

    Returns:
        dict: {
            "URL": str,
            "Valid": bool,
            "Error": str or None,
            "Scheme": str or None,
            "Domain": str or None,
            "Path": str or None
        }
    """
    result = {
        "URL": url,
        "Valid": False,
        "Error": None,
        "Scheme": None,
        "Domain": None,
        "Path": None
    }

    try:
        parsed = urlparse(url)

        # Scheme must be http or https
        if parsed.scheme not in ("http", "https"):
            result["Error"] = "Unsupported or missing scheme"
            return result
        result["Scheme"] = parsed.scheme

        # Domain must exist
        if not parsed.netloc:
            result["Error"] = "Missing domain"
            return result
        result["Domain"] = parsed.netloc

        # Attempt IDNA encode to validate domain characters
        try:
            idna.encode(parsed.netloc)
        except idna.IDNAError:
            result["Error"] = "Invalid internationalized domain"
            return result

        # Valid URL
        result["Path"] = parsed.path
        result["Valid"] = True
        return result

    except Exception as e:
        result["Error"] = str(e)
        return result


if __name__ == "__main__":
    test_urls = [
        "https://example.com",
        "http://sub.domain.co.uk/path",
        "https://café.com/menus",
        "ftp://example.com",               # Unsupported scheme
        "https://",                        # Missing domain
        "https://例子.测试",               # Valid IDN
        "http://localhost",               # Valid localhost
        "https://256.256.256.256",        # Invalid IP but structurally ok
        "https://example.com:8080/page",  # With port
        "not_a_url"                       # Invalid input
    ]

    print("URL Validation Test Results:\n")
    for url in test_urls:
        result = validate_url(url)
        status = "✅" if result["Valid"] else "❌"
        reason = f"({result['Error']})" if result["Error"] else ""
        print(f"{status} {url:40} → Domain: {result['Domain'] or '-'} {reason}")

