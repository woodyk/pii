#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: socialsecurity.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 16:06:37

import re

def validate_socialsecurity(ssn: str) -> dict:
    """
    Validate a U.S. Social Security Number (SSN).

    Args:
        ssn (str): The SSN to validate.

    Returns:
        dict: Validation result with details.
    """
    result = {
        "SSN": ssn,
        "Normalized": None,
        "Valid": False,
        "Error": None
    }

    # Normalize input
    cleaned = ssn.replace("-", "").strip()

    # Check format
    if not re.match(r"^\d{9}$", cleaned):
        result["Error"] = "Invalid format: must be 9 digits"
        return result

    result["Normalized"] = cleaned

    # Extract components
    area, group, serial = int(cleaned[:3]), int(cleaned[3:5]), int(cleaned[5:])

    # Area number validation
    if area == 0 or area == 666 or 900 <= area <= 999:
        result["Error"] = "Invalid area number"
        return result

    # Group number validation
    if group == 0:
        result["Error"] = "Invalid group number"
        return result

    # Serial number validation
    if serial == 0:
        result["Error"] = "Invalid serial number"
        return result

    # Passed all checks
    result["Valid"] = True
    return result


if __name__ == "__main__":
    test_ssns = [
        "123-45-6789",  # Valid
        "666-45-6789",  # Invalid area
        "123-00-6789",  # Invalid group
        "123-45-0000",  # Invalid serial
        "123456789",    # Valid (compact)
        "000-45-6789",  # Invalid area
        "98765432",     # Too short
        "AAA-BB-CCCC",  # Invalid characters
    ]

    print("Social Security Number Validation Test Results:\n")
    for ssn in test_ssns:
        result = validate_socialsecurity(ssn)
        status = "✅" if result["Valid"] else "❌"
        reason = f"({result['Error']})" if result["Error"] else ""
        print(f"{status} {ssn:15}  →  Normalized: {result['Normalized']} {reason}")

