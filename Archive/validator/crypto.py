#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: crypto.py
# Author: Wadih Khairallah
# Description: Validates top 35 cryptocurrency wallet addresses using regex.
# Created: 2025-03-23

import re

# Ethereum-style tokens (ERC-20, EVM chains)
ETH_GROUP = {
    "ETH", "USDT", "USDC", "BNB", "MATIC", "ARB", "LEO", "SHIB",
    "LINK", "UNI", "OKB", "APT", "INJ", "NEAR", "FIL", "ICP", "EGLD", "VET", "HBAR", "ALGO"
}

# Bitcoin-style base58
BTC_GROUP = {"BTC", "WBTC", "BCH", "LTC", "DOGE"}

# Custom regex validators
CRYPTO_REGEX = {
    # Bitcoin & variants
    "BTC": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
    "WBTC": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
    "BCH": r"^(bitcoincash:)?(q|p)[a-z0-9]{41}$",
    "LTC": r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$",
    "DOGE": r"^[DA9][a-km-zA-HJ-NP-Z1-9]{25,34}$",

    # Ethereum & EVM
    "ETH": r"^0x[a-fA-F0-9]{40}$",

    # Ripple
    "XRP": r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$",

    # TRON
    "TRX": r"^T[1-9A-HJ-NP-Za-km-z]{33}$",

    # Monero
    "XMR": r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",

    # Stellar
    "XLM": r"^G[A-Z2-7]{55}$",

    # Cardano (simplified)
    "ADA": r"^(addr1|DdzFF)[0-9a-zA-Z]{10,}$",

    # Polkadot
    "DOT": r"^1[a-km-zA-HJ-NP-Z1-9]{47,50}$",

    # Solana
    "SOL": r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",

    # Toncoin
    "TON": r"^EQ[a-zA-Z0-9_-]{48}$",
}


def validate_crypto_address(address: str, currency: str) -> dict:
    """
    Validate a cryptocurrency wallet address using regex for top 35 coins.

    Args:
        address (str): Wallet address.
        currency (str): Cryptocurrency code (e.g., BTC, ETH, USDT).

    Returns:
        dict: {
            "Address": str,
            "Valid": bool,
            "Currency": str,
            "Error": str or None
        }
    """
    currency = currency.upper()
    result = {
        "Address": address,
        "Valid": False,
        "Currency": currency,
        "Error": None
    }

    # Normalize & assign regex rule
    pattern = CRYPTO_REGEX.get(currency)

    # Group-based rule for EVM tokens
    if not pattern and currency in ETH_GROUP:
        pattern = CRYPTO_REGEX["ETH"]

    # Group-based rule for BTC-derived tokens
    if not pattern and currency in BTC_GROUP:
        pattern = CRYPTO_REGEX["BTC"]

    if not pattern:
        result["Error"] = f"Unsupported currency: {currency}"
        return result

    if re.fullmatch(pattern, address):
        result["Valid"] = True
    else:
        result["Error"] = "Invalid address format"

    return result


if __name__ == "__main__":
    test_addresses = [
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC"),
        ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "BCH"),
        ("LZ3CyqZmbeBikM6SLQ4TB6TxCWAztvwNB3", "LTC"),
        ("D7Y55mD7K33UmSbHj8uhxek76NQC39Sy5j", "DOGE"),
        ("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "ETH"),
        ("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "USDT"),
        ("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb", "TRX"),
        ("r3AddbzLtR7GSdzXGUog2LU6zCwrKDc3vY", "XRP"),
        ("48X60bYkzvvQUeAN5i3zmpfM8H5CDZbHQDcXZ7tEqMWTLvmPZpWLvHz7s5K9ZW7dyhsyUnntTxQkj1hqFPShVpbZNR6kMB9", "XMR"),
        ("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "WBTC"),
        ("GDX4QTZZPWRLFD4FYQGXHO7JD4SYBTEOS75K4JLG7UK23TNX3OM7E4XU", "XLM"),
        ("addr1qxr5m2k5mukqezkn7dkx4vl38c2fh2m6n0zqzr5f2z9uj4nlw9ex0plp5r", "ADA"),
        ("1ZkW4F9f3U1cKyh6oBZ2X8EGPUZZpByJzPKQaWHjS", "DOT"),
        ("4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ", "SOL"),
        ("EQCThW4Y1HeZ2lHvlGQSkCimUt6LBzn8IDP9Zgfd08xIEXpR", "TON"),
        ("abc123", "LOL"),  # Unsupported
        ("", "ETH"),        # Empty
    ]

    print("Cryptocurrency Address Validation Results:\n")
    for addr, currency in test_addresses:
        result = validate_crypto_address(addr, currency)
        status = "✅" if result["Valid"] else "❌"
        reason = f"({result['Error']})" if result["Error"] else ""
        print(f"{status} {addr[:42]:42} → {currency:5} {reason}")

