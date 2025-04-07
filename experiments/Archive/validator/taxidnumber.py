#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: taxidnumber.py
# Author: Wadih Khairallah
# Description: TIN (Tax Identification Number) validation for various countries.
# Created: 2025-03-23

import re

# Country-specific TIN regex patterns
TIN_PATTERNS = {
    "US": r"^\d{3}-?\d{2}-?\d{4}$",                         # SSN
    "India": r"^[A-Z]{5}[0-9]{4}[A-Z]$",                    # PAN
    "UK": r"^[A-CEGHJPR-TW-Z]{2}[0-9]{6}[A-D]$",            # NIN
    "Germany": r"^\d{11}$",                                 # Tax ID
    "France": r"^\d{13}$",                                  # INSEE
    "Canada": r"^\d{3} ?\d{3} ?\d{3}$",                     # SIN
    "Australia": r"^\d{8,9}$",                              # TFN
    "Italy": r"^[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]$",  # Codice Fiscale
    "Spain": r"^[0-9]{8}[A-Z]$",                            # NIF
    "Netherlands": r"^\d{9}$",                              # BSN
    "EU_VAT": r"^[A-Z]{2}[A-Z0-9]{8,12}$",                  # EU VAT format
}


def validate_tin(tin: str, country: str) -> dict:
    """
    Validate a Tax Identification Number (TIN) based on country-specific rules.

    Args:
        tin (str): The TIN to validate.
        country (str): The country name (as per TIN_PATTERNS keys).

    Returns:
        dict: {
            "TIN": str,
            "Valid": bool,
            "Country": str,
            "Error": str or None
        }
    """
    result = {
        "TIN": tin,
        "Valid": False,
        "Country": country,
        "Error": None
    }

    pattern = TIN_PATTERNS.get(country)
    if not pattern:
        result["Error"] = f"Unsupported country: {country}"
        return result

    if not isinstance(tin, str):
        result["Error"] = "TIN must be a string"
        return result

    if re.fullmatch(pattern, tin.strip()):
        result["Valid"] = True
    else:
        result["Error"] = "Invalid format"

    return result


if __name__ == "__main__":
    test_tins = [
        ("123-45-6789", "US"),          # Valid SSN
        ("ABCDE1234F", "India"),        # Valid PAN
        ("AB123456C", "UK"),            # Valid NIN
        ("12345678901", "Germany"),     # Valid Tax ID
        ("1234567890123", "France"),    # Valid INSEE
        ("123 456 789", "Canada"),      # Valid SIN
        ("123456789", "Australia"),     # Valid TFN
        ("RSSMRA85M01H501Z", "Italy"),  # Valid Codice Fiscale
        ("12345678Z", "Spain"),         # Valid NIF
        ("123456789", "Netherlands"),   # Valid BSN
        ("DE123456789", "EU_VAT"),      # Valid VAT
        ("INVALIDTIN", "US"),           # Invalid SSN
        ("12345", "France"),            # Too short
        ("ABCDE1234F", "Germany"),      # Wrong country
    ]

    print("Tax Identification Number Validation Test Results:\n")
    for tin, country in test_tins:
        result = validate_tin(tin, country)
        status = "✅" if result["Valid"] else "❌"
        reason = f"({result['Error']})" if result["Error"] else ""
        print(f"{status} {tin:18} | {country:12} {reason}")

