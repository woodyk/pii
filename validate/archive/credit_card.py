#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: credit_card.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-21 22:01:33
# Modified: 2025-04-21 22:02:35

import re

# Updated BIN/IIN patterns covering major global and regional schemes
NETWORK_REGEX = {
    "American Express":  r"^3[47]\d{13}$",
    "MasterCard":        r"^(?:5[1-5]\d{14}|2(?:2(?:2[1-9]|[3-9]\d)|[3-6]\d{2}|7(?:[01]\d|20))\d{12})$",
    "Visa":              r"^4\d{12}(?:\d{3})?(?:\d{3})?$",
    "Discover":          r"^(?:6011\d{12}|65\d{14}|64[4-9]\d{13}|622(?:12[6-9]|1[3-9]\d|[2-8]\d{2}|9(?:[01]\d|2[0-5]))\d{10})$",
    "Diners Club":       r"^3(?:0[0-5]|[68]\d)\d{11}$",
    "JCB":               r"^35(?:2[89]|[3-8]\d)\d{12,15}$",
    "Maestro":           r"^(?:50[129]|5[6-9]\d|6\d{2})\d{10,17}$",
    "Visa Electron":     r"^(?:4026|417500|4508|4844|491[37])\d{8,15}$",
    "UnionPay":          r"^62\d{14,17}$",
    "Mir":               r"^220[0-4]\d{12}$",
    "Elo":               r"^(?:4011|4312|4389|4514|4576|5041(?:73|74|75)|5067\d|509\d|627780|636297|636368|636369)\d{10,12}$",
    "RuPay":             r"^(?:60|65|6521|6522)\d{11,14}$",
    "Troy":              r"^9792\d{12}$",
    "Dankort":           r"^5019\d{12}$",
    "BC Card":           r"^(?:3569|4579|4895|4945|5631|5893)\d{10,12}$",
    "InterPayment":      r"^636\d{13}$",
    "InstaPayment":      r"^63[7-9]\d{13}$",
    "Laser":             r"^6304\d{12,15}$",
    "Solo":              r"^(?:6334|6767)\d{12,14}$",
    "Switch":            r"^(?:490[3-5]|4911|4936|564182|633110|6333|6759)\d{8,12}$",
    "UATP":              r"^1(?:0|5)\d{13}$",
    "Verve":             r"^(?:506099|650002|650027|507865|507964)\d{10,13}$",
}

def validate_credit_card(raw_cc) -> dict:
    """
    Normalize, classify, and validate a credit card number.
    Accepts raw_cc as any type (str, int, etc.) and coerces to string.
    Returns a dict:
      - valid: True if brand detected & Luhn check passes
      - luhn_valid: True/False
      - brand: network name or None
      - length: number of digits
      - iin: first 6 digits (or full number if shorter)
      - mii: first digit as int or None
      - mii_description: industry description for the MII digit
      - check_digit: last digit of the card number
    """
    # Major Industry Identifier descriptions
    MII_MAPPING = {
        0: "ISO/TC 68 and other industry assignments",
        1: "Airlines",
        2: "Airlines and future industry assignments",
        3: "Travel and entertainment",
        4: "Banking and financial",
        5: "Banking and financial",
        6: "Merchandising and banking",
        7: "Petroleum",
        8: "Healthcare, telecommunications and other",
        9: "National assignment"
    }

    # 1) Coerce to string and normalize: keep only digits
    raw = str(raw_cc or "")
    cc = re.sub(r"\D", "", raw)
    length = len(cc)
    iin = cc[:6] if length >= 6 else cc
    mii = int(cc[0]) if length >= 1 else None
    check_digit = int(cc[-1]) if length >= 1 else None

    # 2) Quick reject: most cards are 12–19 digits
    if not (12 <= length <= 19):
        return {
            "valid": False,
            "luhn_valid": False,
            "brand": None,
            "length": length,
            "iin": iin,
            "mii": mii,
            "mii_description": MII_MAPPING.get(mii),
            "check_digit": check_digit
        }

    # 3) Luhn check
    digits = [int(d) for d in cc]
    total = sum(digits[-1::-2])
    for d in digits[-2::-2]:
        dbl = d * 2
        total += (dbl // 10) + (dbl % 10)
    luhn_ok = (total % 10 == 0)

    # 4) Brand detection by regex
    brand = None
    for name, pattern in NETWORK_REGEX.items():
        if re.match(pattern, cc):
            brand = name
            break

    valid = bool(brand) and luhn_ok

    return {
        "valid": valid,
        "luhn_valid": luhn_ok,
        "brand": brand,
        "length": length,
        "iin": iin,
        "mii": mii,
        "mii_description": MII_MAPPING.get(mii),
        "check_digit": check_digit
    }


if __name__ == "__main__":
    import json

    cc_tests = [
        "4111 1111 1111 1111",        # Visa
        "5105-1051-0510-5100",        # MasterCard
        "378282246310005",            # American Express
        "1234 5678 9012 345",         # invalid
    ]
    print("\n=== Credit Card Validation ===")
    for cc in cc_tests:
        result = validate_credit_card(cc)
        print(f"\nInput: {cc}")
        print(json.dumps(result, indent=2))
