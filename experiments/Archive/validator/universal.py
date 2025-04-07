#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: universal.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 17:02:59

import importlib
from stdnum.exceptions import ValidationError

# List of common stdnum modules to test for (you can expand this)
stdnum_modules = [
    "iban", "bic", "vat", "isbn", "issn", "imei", "vin", "ssn",
    "luhn", "mac", "bitcoin", "in_.pan", "us.ein", "us.itin",
    "de.idnr", "fr.nir", "cn.uscc", "es.nif", "br.cpf", "br.cnpj",
    "pl.nip", "pl.pesel", "se.personnummer", "nl.bsn",
    "checkdigit.verhoeff", "checkdigit.damm"
]

def validate_any(input_str: str) -> dict:
    """
    Try all known stdnum validators on the input and return info about it.
    """
    input_str = input_str.strip()
    result = {
        "Input": input_str,
        "Valid": False,
        "Type": None,
        "Module": None,
        "Normalized": None,
        "Metadata": {},
        "Error": None
    }

    for modname in stdnum_modules:
        try:
            module = importlib.import_module(f"stdnum.{modname}")
            if module.is_valid(input_str):
                result["Valid"] = True
                result["Type"] = modname.upper()
                result["Module"] = modname
                result["Normalized"] = module.compact(input_str)
                if hasattr(module, "info"):
                    try:
                        result["Metadata"] = module.info(input_str)
                    except Exception as info_err:
                        result["Metadata"] = {"error": str(info_err)}
                break
        except ValidationError:
            continue
        except Exception:
            continue  # skip broken modules silently

    if not result["Valid"]:
        result["Error"] = "No known stdnum format matched."

    return result


if __name__ == "__main__":
    test_inputs = [
        "DE44500105175407324931",  # IBAN
        "DEUTDEFF",                # SWIFT/BIC
        "9780306406157",           # ISBN
        "031234567",               # US SSN
        "52998224725",             # BR CPF
        "356938035643809",         # IMEI
        "1HGCM82633A004352",       # VIN
        "1A3G123",                 # Unknown
    ]

    print("Universal Validator Test Results:\n")
    for test in test_inputs:
        res = validate_any(test)
        status = "✅" if res["Valid"] else "❌"
        print(f"{status} {test:30} Type: {res['Type']}  Module: {res['Module']}")
        if res["Metadata"]:
            print(f"     ↳ Metadata: {res['Metadata']}")
        if res["Error"]:
            print(f"     ✖ Error: {res['Error']}")

