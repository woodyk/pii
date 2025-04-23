#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: routing_number.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-22 00:03:32
# Modified: 2025-04-22 01:36:13

import re
import json

# Sample ABA_ROUTING_DATA, replace with actual data import
ABA_ROUTING_DATA = [
    {
        "routing_number": "011000015",
        "institution_name": "FEDERAL RESERVE BANK OF BOSTON",
        "city": "BOSTON",
        "state": "MA",
        "funds_settlement": "Y",
        "funds_transfer": "Y",
        "date_active": "20040910"
    },
    # Add more entries here for testing...
]

def validate_routing_number(routing_number: str) -> bool:
    """
    Validates a U.S. bank routing number using the ABA check digit algorithm.
    Args:
        routing_number (str): The 9-digit routing number to validate.
    Returns:
        bool: True if the routing number is valid, False otherwise.
    """
    if not isinstance(routing_number, str) or len(routing_number) != 9 or not routing_number.isdigit():
        return False

    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    checksum = sum(int(digit) * weight for digit, weight in zip(routing_number, weights)) % 10

    return checksum == 0

def extract_metadata(routing_number: str) -> dict:
    """
    Extract metadata for a U.S. bank routing number if it exists in ABA_ROUTING_DATA.
    Args:
        routing_number (str): The 9-digit routing number.
    Returns:
        dict: Metadata including bank name, city, state, and more.
    """
    result = {
        "routing_number": routing_number,
        "institution_name": None,
        "city": None,
        "state": None,
        "funds_settlement": None,
        "funds_transfer": None,
        "date_active": None,
        "error": None
    }

    # Check if routing number exists in ABA_ROUTING_DATA (dummy data here)
    match = next((entry for entry in ABA_ROUTING_DATA if entry["routing_number"] == routing_number), None)
    if match:
        result.update({
            "institution_name": match["institution_name"],
            "city": match["city"],
            "state": match["state"],
            "funds_settlement": match["funds_settlement"],
            "funds_transfer": match["funds_transfer"],
            "date_active": match["date_active"]
        })
    else:
        result["error"] = f"Routing number {routing_number} not found in dataset"

    return result

def validate_and_extract(routing_number: str) -> dict:
    """
    Validate a routing number and extract all available metadata.
    Args:
        routing_number (str): The 9-digit routing number to validate and extract.
    Returns:
        dict: Validation result and extracted metadata.
    """
    is_valid = validate_routing_number(routing_number)
    metadata = extract_metadata(routing_number)

    result = {
        "valid": is_valid,
        "checksum_valid": is_valid,
        "routing_number": routing_number,
        "institution_name": metadata["institution_name"],
        "city": metadata["city"],
        "state": metadata["state"],
        "funds_settlement": metadata["funds_settlement"],
        "funds_transfer": metadata["funds_transfer"],
        "date_active": metadata["date_active"],
        "error": metadata["error"]
    }

    return result

if __name__ == "__main__":
    # Test routing numbers (you can add more or dynamically test)
    test_routing_numbers = [
        "011000015",  # Valid routing number
        "123456789",  # Invalid routing number
        "063107513",
    ]

    for routing in test_routing_numbers:
        result = validate_and_extract(routing)
        print(f"\nRouting number: {routing}")
        print(json.dumps(result, indent=2, ensure_ascii=False))
