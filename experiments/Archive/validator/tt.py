#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: tt.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 17:40:43
# Modified: 2025-03-23 17:54:20

import importlib
import pkgutil
import re
import ipaddress
import uuid
from stdnum.exceptions import ValidationError

def get_all_stdnum_modules():
    import stdnum
    modules = []
    for _, name, ispkg in pkgutil.walk_packages(stdnum.__path__, prefix='stdnum.'):
        if not ispkg:
            modules.append(name)
    return modules

def try_stdnum_modules(value: str):
    results = []
    for modname in get_all_stdnum_modules():
        try:
            mod = importlib.import_module(modname)
            if not hasattr(mod, 'is_valid') or not mod.is_valid(value):
                continue
            result = {
                "Type": modname.replace("stdnum.", ""),
                "Valid": True,
                "Normalized": None,
                "Formatted": None,
                "Metadata": {}
            }
            if hasattr(mod, "compact"):
                try:
                    result["Normalized"] = mod.compact(value)
                except Exception:
                    pass
            if hasattr(mod, "format"):
                try:
                    result["Formatted"] = mod.format(value)
                except Exception:
                    pass
            if hasattr(mod, "info"):
                try:
                    result["Metadata"] = mod.info(value)
                except Exception as info_err:
                    result["Metadata"] = {"error": str(info_err)}
            results.append(result)
        except ValidationError:
            continue
        except Exception:
            continue
    return results

def validate_email(value: str) -> dict:
    if re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", value):
        return {"Type": "Email", "Valid": True}
    return {"Type": "Email", "Valid": False}

def validate_ip(value: str) -> dict:
    try:
        ip = ipaddress.ip_address(value)
        return {
            "Type": "IPv4" if ip.version == 4 else "IPv6",
            "Valid": True,
            "Metadata": {
                "Is Private": ip.is_private,
                "Is Multicast": ip.is_multicast,
                "Is Loopback": ip.is_loopback
            }
        }
    except ValueError:
        return {"Type": "IP", "Valid": False}

def validate_uuid(value: str) -> dict:
    try:
        u = uuid.UUID(value)
        return {"Type": "UUID", "Valid": True, "Normalized": str(u)}
    except ValueError:
        return {"Type": "UUID", "Valid": False}

def validate_any(input_str: str) -> list:
    input_str = input_str.strip()
    results = []

    stdnum_matches = try_stdnum_modules(input_str)
    if stdnum_matches:
        results.extend(stdnum_matches)

    custom_funcs = [validate_email, validate_ip, validate_uuid]
    for func in custom_funcs:
        res = func(input_str)
        if res.get("Valid"):
            results.append(res)

    if not results:
        results.append({
            "Type": "Unknown",
            "Input": input_str,
            "Valid": False,
            "Error": "No known format matched."
        })

    return results


if __name__ == "__main__":
    test_inputs = [
        "DE44500105175407324931",  # IBAN
        "DEUTDEFF",                # BIC
        "9780306406157",           # ISBN
        "52998224725",             # BR CPF
        "1HGCM82633A004352",       # VIN
        "2T3W1RFV1MW468219",       # VIN (real)
        "4111111111111111",        # Credit card (Luhn)
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",  # BTC
        "192.168.1.1",             # IP
        "::1",                     # IPv6
        "test@example.com",        # Email
        "550e8400-e29b-41d4-a716-446655440000",  # UUID
        "INVALID12345",       # Unknown
        "2T3WFREV1JW468219"
    ]

    for value in test_inputs:
        print(f"\n🧪 Input: {value}")
        for result in validate_any(value):
            print(result)
            print(f"  ✅ Type: {result.get('Type')}")
            print(f"     - Valid: {result.get('Valid')}")
            if 'Normalized' in result: print(f"     - Normalized: {result.get('Normalized')}")
            if 'Formatted' in result: print(f"     - Formatted: {result.get('Formatted')}")
            if 'Metadata' in result and result['Metadata']:
                print(f"     - Metadata: {result['Metadata']}")
            if 'Error' in result and result['Error']:
                print(f"     - Error: {result['Error']}")

