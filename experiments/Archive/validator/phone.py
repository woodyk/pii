#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: phone.py
# Author: Wadih Khairallah
# Description: Phone number validation for US and international formats.
# Created: 2025-03-23 15:59:25

import re
import math
from collections import Counter


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy


def validate_phone(phone_number: str) -> dict:
    """
    Validate a phone number for both US and international formats.

    Args:
        phone_number (str): The input phone number string.

    Returns:
        dict: {
            "Phone Number": str,
            "Normalized": str or None,
            "Valid": bool,
            "Type": "US" | "International" | "Invalid"
        }
    """
    raw = phone_number
    phone_number = phone_number.strip()

    result = {
        "Phone Number": raw,
        "Normalized": None,
        "Valid": False,
        "Type": "Invalid"
    }

    # Remove extensions and normalize formatting
    cleaned = re.sub(r'(?:ext\.?|x)\d+$', '', phone_number, flags=re.IGNORECASE)
    cleaned = re.sub(r'[^\d+]', '', cleaned)
    digits_only = re.sub(r'\D', '', cleaned)

    if not (7 <= len(digits_only) <= 15):
        result["Normalized"] = digits_only
        return result

    if calculate_entropy(digits_only) < 2.5:
        result["Normalized"] = digits_only
        return result

    pattern = re.compile(r"^\+?[1-9]\d{6,14}$")
    if pattern.match(cleaned):
        result["Normalized"] = cleaned
        if cleaned.startswith("+1") or (len(digits_only) == 10 and digits_only[0] in "2-9"):
            result["Valid"] = True
            result["Type"] = "US"
        else:
            result["Valid"] = True
            result["Type"] = "International"
    else:
        result["Normalized"] = digits_only

    return result


if __name__ == "__main__":
    test_numbers = [
        "+11234567890",      # US with country code
        "(123) 456-7890",    # Common US format
        "123-456-7890",      # US format
        "+442071838750",     # UK international
        "+919876543210",     # India international
        "987654321",         # Short international
        "+1-800-555-1234",   # US toll-free
        "18005551234",       # US toll-free compact
        "0000000000",        # Invalid (low entropy)
        "999999999999999999" # Invalid (too long)
    ]

    print("Phone Number Validation Test Results:\n")
    for number in test_numbers:
        result = validate_phone(number)
        status = "✅" if result["Valid"] else "❌"
        normalized = result["Normalized"] or "-"
        print(f"{status} {number:20} → Type: {result['Type']:14} | Normalized: {normalized}")

