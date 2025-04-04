#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: bankaccount.py
# Author: Wadih Khairallah
# Description: Validates and decodes banking numbers using stdnum and schwifty.
# Created: 2025-03-23
# Modified: 2025-03-23 16:52:32

import re
from stdnum import iban as std_iban
from stdnum import bic as std_bic
import schwifty

def validate_iban(iban_str: str) -> dict:
    result = {
        "IBAN": iban_str,
        "Valid": False,
        "Error": None,
        "Country": None,
        "Bank Code": None,
        "Account Code": None
    }

    try:
        if not std_iban.is_valid(iban_str):
            result["Error"] = "Invalid IBAN structure or checksum"
            return result

        obj = schwifty.IBAN(iban_str)
        result.update({
            "Valid": True,
            "Country": obj.country_code,
            "Bank Code": obj.bank_code,
            "Account Code": obj.account_code
        })
    except Exception as e:
        result["Error"] = str(e)

    return result


def validate_swift(swift_code: str) -> dict:
    result = {
        "SWIFT Code": swift_code,
        "Valid": False,
        "Error": None,
        "Bank Code": None,
        "Country Code": None,
        "Location Code": None,
        "Branch Code": None
    }

    try:
        if not std_bic.is_valid(swift_code):
            result["Error"] = "Invalid SWIFT/BIC format"
            return result

        bic = schwifty.BIC(swift_code)
        result.update({
            "Valid": True,
            "Bank Code": bic.bank_code,
            "Country Code": bic.country_code,
            "Location Code": bic.location_code,
            "Branch Code": bic.branch_code or "N/A"
        })
    except Exception as e:
        result["Error"] = str(e)

    return result


def validate_bank_account(account: str) -> dict:
    """
    High-level entry point for IBAN or SWIFT account codes.
    """
    account = account.strip().replace(" ", "")
    if re.match(r"^[A-Z]{2}\d{2}", account):  # IBAN
        return validate_iban(account)
    elif re.match(r"^[A-Z]{6}[A-Z0-9]{2,5}$", account):  # SWIFT/BIC
        return validate_swift(account)
    else:
        return {
            "Account": account,
            "Valid": False,
            "Error": "Unknown or unsupported account format"
        }


if __name__ == "__main__":
    print("Bank Identifier Validation (IBAN / SWIFT):\n")

    test_accounts = [
        "DE44500105175407324931",   # Valid IBAN (Germany)
        "GB82WEST12345698765432",   # Valid IBAN (UK)
        "FR7630006000011234567890189",  # Valid IBAN (France)
        "DEUTDEFF",                 # Valid SWIFT
        "DEUTDEFF500",             # Valid SWIFT with branch
        "FOOBAD123",               # Invalid SWIFT
        "INVALIDIBAN123"           # Invalid IBAN
    ]

    for account in test_accounts:
        result = validate_bank_account(account)
        status = "✅" if result.get("Valid") else "❌"
        error = f"({result['Error']})" if result.get("Error") else ""
        print(f"{status} {account:30} {error}")
        if result.get("Valid"):
            if "Bank Code" in result:
                print(f"     Bank Code: {result['Bank Code']}  Account: {result.get('Account Code', '-')}")
            if "Country" in result:
                print(f"     Country: {result['Country']}")

