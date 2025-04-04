#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: emailaddress.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 16:03:29
# Modified: 2025-03-23 16:52:20

import re
import idna

def validate_email(email: str) -> dict:
    """
    Validate an email address based on RFC 5322 standards and domain sanity.

    Args:
        email (str): The email address to validate.

    Returns:
        dict: Validation result with details.
    """
    result = {
        "Email": email,
        "Valid": False,
        "Error": None
    }

    if not isinstance(email, str) or "@" not in email:
        result["Error"] = "Missing @ or invalid type"
        return result

    try:
        local, domain = email.rsplit("@", 1)
    except ValueError:
        result["Error"] = "Email must contain exactly one '@'"
        return result

    # Encode domain to punycode to catch IDN issues
    try:
        idna.encode(domain)
    except idna.IDNAError:
        result["Error"] = "Invalid international domain"
        return result

    # Email pattern (simple RFC 5322 approximation)
    email_regex = re.compile(
        r"^(?!(?:(?:\x22)?\x2e|\x22\x2e)(?:.*\x40))"
        r".+@"
        r"(?:(?!\x2e)[A-Za-z0-9][A-Za-z0-9-]{0,62}[A-Za-z0-9]?\x2e)"
        r"{1,126}[A-Za-z]{2,63}$"
    )

    if not email_regex.match(email):
        result["Error"] = "Invalid email format"
        return result

    result["Valid"] = True
    return result


if __name__ == "__main__":
    test_emails = [
        "simple@example.com",
        "very.common@example.com",
        "user+alias@sub.domain.com",
        "user.name+tag+sorting@example.com",
        "user@localserver",
        "@missinglocal.com",
        "missingdomain@",
        "user.@example.com",
        "user@.com",
        "invalid@xn--caf-dma.com"  # punycode domain
    ]

    print("Email Validation Test Results:\n")
    for email in test_emails:
        result = validate_email(email)
        status = "✅" if result["Valid"] else "❌"
        reason = f"({result['Error']})" if result["Error"] else ""
        print(f"{status} {email:40} {reason}")

