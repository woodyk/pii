#!/usr/bin/env python3
#
# regex_pii_extract.py

import re

def extract_high_confidence_pii(text):
    patterns = {
        'AADHAAR': r'\b\d{12}\b',
        'AUSTRALIAN_ABN': r'\b\d{11}\b',
        'BRAZILIAN_CPF': r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b',
        'CREDIT_CARD': r'\b(?:\d[ -]*?){13,19}\b',
        'EMAIL': r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b',
        'IBAN': r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',
        'IPV4_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'IPV6_ADDRESS': r'\b([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b',
        'MAC_ADDRESS': r'\b[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}\b',
        'US_PASSPORT': r'\b\d{9}\b',
        'PHONE_NUMBER': r'\b\+?\d{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'SSN': r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
        'TIME': r'\b([01]?\d|2[0-3]):[0-5]\d(:[0-5]\d)?\b'
    }

    extracted_data = {}

    for key, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            extracted_data[key] = matches

    return extracted_data

# Example usage
text = """
Here are some phone numbers: +1-123-456-7890, (123) 456-7890, 123.456.7890, 123 456 7890, 1234567890, +44 123 456 7890.
Here are some SSNs: 123-45-6789, 123.45.6789, 123 45 6789, and 123456789.
My MAC addresses could be 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E.
"""
extracted_pii = extract_high_confidence_pii(text)
print(extracted_pii)

