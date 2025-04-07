#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: creditcard.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 16:05:43

import re

def luhn_algorithm(card_number: str) -> bool:
    """Validates credit card number using the Luhn algorithm."""
    card_number = card_number.replace(" ", "")
    if not card_number.isdigit():
        return False

    check_digit = int(card_number[-1])
    reversed_digits = [int(d) for d in card_number[-2::-1]]

    for i in range(0, len(reversed_digits), 2):
        doubled = reversed_digits[i] * 2
        if doubled > 9:
            doubled -= 9
        reversed_digits[i] = doubled

    return (sum(reversed_digits) + check_digit) % 10 == 0

def detect_card_type(card_number: str) -> str:
    """Identifies card type using regex patterns."""
    card_patterns = {
        "Visa": r"^4[0-9]{12}(?:[0-9]{3})?$",
        "MasterCard": r"^5[1-5][0-9]{14}$",
        "American Express": r"^3[47][0-9]{13}$",
        "Discover": r"^6(?:011|5[0-9]{2})[0-9]{12}$",
        "Diners Club": r"^3(?:0[0-5]|[68][0-9])[0-9]{11}$",
        "JCB": r"^(?:2131|1800|35\d{3})\d{11}$",
        "UnionPay": r"^62[0-9]{14,17}$",
    }

    for card_type, pattern in card_patterns.items():
        if re.match(pattern, card_number):
            return card_type
    return "Unknown"

def validate_credit_card(card_number: str) -> dict:
    """
    Validate and identify a credit card number.

    Args:
        card_number (str): The credit card number to validate.

    Returns:
        dict: A dictionary with the validation results.
    """
    normalized = re.sub(r"\D", "", card_number)
    card_type = detect_card_type(normalized)
    valid = luhn_algorithm(normalized)

    return {
        "Card Number": card_number,
        "Normalized": normalized,
        "Card Type": card_type,
        "Valid": valid
    }


if __name__ == "__main__":
    test_cards = [
        "4111 1111 1111 1111",  # Visa
        "5555 5555 5555 4444",  # MasterCard
        "378282246310005",      # AmEx
        "6011111111111117",     # Discover
        "30569309025904",       # Diners Club
        "3530111333300000",     # JCB
        "6221260000000000",     # UnionPay
        "1234 5678 9012 3456",  # Invalid
        "4111-1111-1111-1111",  # Visa with dashes
    ]

    print("Credit Card Validation Test Results:\n")
    for card in test_cards:
        result = validate_credit_card(card)
        status = "✅" if result["Valid"] else "❌"
        print(f"{status} {card:23} | Type: {result['Card Type']:15} | Normalized: {result['Normalized']}")

