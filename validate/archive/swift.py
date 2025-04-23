#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: swift.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-21 22:02:24
# Modified: 2025-04-21 22:02:41

import re
import pycountry


# Precompute valid ISO 3166‑1 alpha‑2 country codes and names
_VALID_COUNTRY_CODES = {c.alpha_2 for c in pycountry.countries}
_COUNTRY_NAME_MAP = {c.alpha_2: c.name for c in pycountry.countries}

def validate_swift(swift_code: str) -> dict:
    """
    Validate and extract metadata from a SWIFT/BIC code.

    Returns a dict with:
      - swift          : normalized code (upper‑case)
      - valid          : True if all checks pass
      - format         : "primary" for 8‑char BIC or "branch" for 11‑char BIC
      - bank_code      : first 4 letters (institution)
      - country_code   : 2‑letter ISO 3166‑1 alpha‑2 code
      - country        : full country name (or None)
      - location_code  : 2‑char location (city/region)
      - passive        : True if location_code[1] == "0" (non‑financial)
      - test           : True if location_code[1] == "1" (test BIC)
      - branch_code    : 3‑char branch identifier or "XXX"
      - primary_office : True if branch_code == "XXX"
      - error          : None or one of "invalid_length", "invalid_format", "invalid_country"
    """
    code = (swift_code or "").strip().upper()
    result = {
        "swift": code,
        "valid": False,
        "format": None,
        "bank_code": None,
        "country_code": None,
        "country": None,
        "location_code": None,
        "passive": None,
        "test": None,
        "branch_code": None,
        "primary_office": None,
        "error": None
    }

    # 1) Length must be exactly 8 or 11
    if len(code) not in (8, 11):
        result["error"] = "invalid_length"
        return result

    # 2) Format per ISO 9362
    if not re.fullmatch(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$", code):
        result["error"] = "invalid_format"
        return result

    # 3) Extract components
    bank_code     = code[0:4]
    country_code  = code[4:6]
    location_code = code[6:8]
    branch_code   = code[8:] if len(code) == 11 else "XXX"

    # 4) Country validation
    if country_code not in _VALID_COUNTRY_CODES:
        result["error"] = "invalid_country"
        return result
    country_name = _COUNTRY_NAME_MAP[country_code]

    # 5) Populate metadata
    result.update({
        "valid": True,
        "format": "primary" if len(code) == 8 else "branch",
        "bank_code": bank_code,
        "country_code": country_code,
        "country": country_name,
        "location_code": location_code,
        "passive": location_code[1] == "0",
        "test": location_code[1] == "1",
        "branch_code": branch_code,
        "primary_office": (branch_code == "XXX"),
        "error": None
    })

    return result

if __name__ == "__main__":
    import json

    swift_tests = [
        "DEUTDEFF",        # 8‑char primary
        "NEDSZAJJXXX",     # 11‑char branch
        "INVALID1",        # bad length
        "BOFAUS3NXXX",     # valid US branch
    ]

    print("\n=== SWIFT Code Validation ===")
    for code in swift_tests:
        result = validate_swift(code)
        print(f"\nInput: {code}")
        print(json.dumps(result, indent=2))
