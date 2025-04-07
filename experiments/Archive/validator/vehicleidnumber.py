#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: vehicleidnumber.py
# Author: Wadih Khairallah
# Description: Validates and decodes Vehicle Identification Numbers (VINs).
# Created: 2025-03-23
# Modified: 2025-03-23 17:45:38

def validate_vin(vin: str) -> dict:
    """
    Validates a Vehicle Identification Number (VIN) using ISO 3779 checksum.

    Args:
        vin (str): The VIN to validate.

    Returns:
        dict: {
            "VIN": str,
            "Valid": bool,
            "Error": str or None
        }
    """
    result = {
        "VIN": vin,
        "Valid": False,
        "Error": None
    }

    if len(vin) != 17 or not vin.isalnum():
        result["Error"] = "VIN must be 17 alphanumeric characters"
        return result

    if any(c in vin for c in "IOQ"):
        result["Error"] = "VIN contains invalid characters: I, O, or Q"
        return result

    letter_map = {
        "A": 1, "B": 2, "C": 3, "D": 4, "E": 5,
        "F": 6, "G": 7, "H": 8, "J": 1, "K": 2,
        "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
        "S": 2, "T": 3, "U": 4, "V": 5, "W": 6,
        "X": 7, "Y": 8, "Z": 9
    }

    weights = [8, 7, 6, 5, 4, 3, 2, 10,
               0, 9, 8, 7, 6, 5, 4, 3, 2]

    def transliterate(c):
        if c.isdigit():
            return int(c)
        return letter_map.get(c.upper(), 0)

    transliterated = [transliterate(c) for c in vin]
    weighted_sum = sum(v * w for v, w in zip(transliterated, weights))
    checksum = weighted_sum % 11
    check_digit = vin[8]

    if checksum == 10:
        valid = check_digit == "X"
    else:
        valid = check_digit == str(checksum)

    if valid:
        result["Valid"] = True
    else:
        result["Error"] = f"Checksum mismatch (expected {checksum if checksum != 10 else 'X'})"

    return result


def decode_vin(vin: str) -> dict:
    """
    Decodes basic VIN fields: WMI, VDS, VIS, year, plant, serial.

    Args:
        vin (str): The VIN to decode.

    Returns:
        dict: Decoded VIN components.
    """
    if len(vin) != 17:
        return {"Error": "VIN must be 17 characters"}

    year_codes = {
        "A": 1980, "B": 1981, "C": 1982, "D": 1983, "E": 1984,
        "F": 1985, "G": 1986, "H": 1987, "J": 1988, "K": 1989,
        "L": 1990, "M": 1991, "N": 1992, "P": 1993, "R": 1994,
        "S": 1995, "T": 1996, "V": 1997, "W": 1998, "X": 1999,
        "Y": 2000, "1": 2001, "2": 2002, "3": 2003, "4": 2004,
        "5": 2005, "6": 2006, "7": 2007, "8": 2008, "9": 2009,
        # Repeats after 2009 with same codes
    }

    vin = vin.upper()
    decoded = {
        "VIN": vin,
        "WMI": vin[0:3],
        "VDS": vin[3:9],
        "Check Digit": vin[8],
        "Model Year Code": vin[9],
        "Plant Code": vin[10],
        "Serial Number": vin[11:],
        "VIS": vin[9:],
        "Error": None
    }

    year_code = vin[9]
    decoded["Model Year"] = year_codes.get(year_code, "Unknown")

    return decoded


if __name__ == "__main__":
    test_vins = [
        "1HGCM82633A004352",  # Valid
        "1HGCM82633A00435X",  # Invalid checksum
        "1HGCM82633A00435I",  # Invalid char
        "WBA3A5C54FF607427",  # Valid format, test BMW VIN
        "2T3WFREV1JW468219",
    ]

    print("VIN Validation and Decoding Results:\n")
    for vin in test_vins:
        val_result = validate_vin(vin)
        status = "✅" if val_result["Valid"] else "❌"
        print(f"{status} {vin:20} {val_result['Error'] or ''}")

        if val_result["Valid"]:
            decoded = decode_vin(vin)
            print(f"     WMI: {decoded['WMI']} | VDS: {decoded['VDS']} | Year: {decoded['Model Year']} | Plant: {decoded['Plant Code']} | Serial: {decoded['Serial Number']}")

