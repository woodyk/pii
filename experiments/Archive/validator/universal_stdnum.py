#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: universal_stdnum.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 17:44:23
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: universal_validator_stdnum.py
# Description: Validates any known stdnum-compatible format and returns details.

import pkgutil
import importlib
from stdnum.exceptions import ValidationError

def get_all_stdnum_modules():
    """Dynamically collect all stdnum modules."""
    import stdnum
    modules = []
    for _, name, ispkg in pkgutil.walk_packages(stdnum.__path__, prefix='stdnum.'):
        if not ispkg:
            modules.append(name)
    return modules


def validate_with_stdnum(input_str: str) -> list:
    """
    Attempt validation with all known stdnum modules.

    Returns:
        List[dict] with fields:
        - Module
        - Valid
        - Normalized
        - Formatted
        - Metadata
    """
    input_str = input_str.strip()
    results = []

    for modname in get_all_stdnum_modules():
        try:
            mod = importlib.import_module(modname)

            if not hasattr(mod, 'is_valid') or not mod.is_valid(input_str):
                continue

            result = {
                "Module": modname.replace("stdnum.", ""),
                "Valid": True,
                "Normalized": None,
                "Formatted": None,
                "Metadata": {}
            }

            if hasattr(mod, "compact"):
                try:
                    result["Normalized"] = mod.compact(input_str)
                except Exception:
                    pass

            if hasattr(mod, "format"):
                try:
                    result["Formatted"] = mod.format(input_str)
                except Exception:
                    pass

            if hasattr(mod, "info"):
                try:
                    result["Metadata"] = mod.info(input_str)
                except Exception as e:
                    result["Metadata"] = {"error": str(e)}

            results.append(result)

        except ValidationError:
            continue
        except Exception:
            continue

    return results


if __name__ == "__main__":
    test_inputs = [
        # Banking / IBAN / BIC
        "DE44500105175407324931",  # German IBAN
        "GB82WEST12345698765432",  # UK IBAN
        "DEUTDEFF",                # SWIFT/BIC

        # Identity Numbers
        "031234567",               # US SSN
        "52998224725",             # BR CPF
        "12345678909",             # Another BR CPF (valid)
        "12345678901234",          # FR NIR (likely to fail info)

        # ISBN / Media / Barcode
        "9780306406157",           # ISBN
        "12345678",                # EAN/UPC (possibly valid)
        "ISRC12345678",            # ISRC (if formatted right)
        "USRC17607839",            # Valid ISRC

        # Corporate / Tax
        "04-3691632",              # US EIN
        "KRA123456789A",           # KE PIN (check formatting)
        "RUC12345678901",          # EC or PE RUC

        # Crypto / Luhn / Checksum
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",  # Bitcoin address
        "4111111111111111",        # Visa test card (Luhn)
        "79927398713",             # Classic Luhn-valid

        # VINs
        "1HGCM82633A004352",       # Valid Honda VIN
        "2T3WFREV1JW468219",       # Real Toyota VIN (fails checksum)

        # Misc
        "356938035643809",         # IMEI
        "AA123456789",             # Possibly PAN
        "1234567X",                # Danish CPR or invalid
        "XY1234567",               # Unknown
    ]

    for item in test_inputs:
        print(f"\n🔍 Input: {item}")
        matches = validate_with_stdnum(item)
        if not matches:
            print("❌ No stdnum module matched.")
        for match in matches:
            print(f"✅ Module: {match['Module']}")
            print(f"    Normalized: {match['Normalized']}")
            print(f"    Formatted:  {match['Formatted']}")
            print(f"    Metadata:   {match['Metadata']}")

        print(f"----------------------------")

