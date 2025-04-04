#!/usr/bin/env python3
#
# pii_model_extraction.py

from transformers import pipeline
import json

# Initialize the PII detection pipeline
gen = pipeline("token-classification", model="h2oai/deberta_finetuned_pii", device=-1)

# Sample text containing various PII data types
text = """
8.2 Driver's License
A driver's license number might be D123456789012.

8.3 Driver's License (International)
An international driver's license number might look like INTD123456.

8.4 Time
Time is typically represented in formats such as 13:45 or 7:30 PM.

8.5 Username
Usernames are unique identifiers in digital platforms, such as john_doe_1985.

social security 584-89-0092 ssn number identifier taxpayer

The routing number is 123456789. You can also write it as 123-456-789 or 123 456 789. The routing number 021000021 is for JPMorgan Chase Bank in Florida, and 111000038 is for the Federal Reserve Bank in Minneapolis.
    John Doe's email is john.doe@example.com and his phone number is +1-555-555-5555.
    His SSN is 123-45-6789. He often shops online using his credit card number 1234 5678 9101 1121.
    His bank account number is 12345678901, and the routing number is 021000021.
    He drives a vehicle with VIN 1HGCM82633A123456 and holds a driver's license number D12345678.
    He has a meeting scheduled on 15th July 2023 at 10:30 AM.
    Visit https://example.com for more details.
    His server's IP addresses are 192.168.1.1/24 and 2001:db8::/32.
    Another IPv6 address is 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
    The headquarters is located at 1600 Pennsylvania Ave NW, Washington, DC 20500.
    His current location is at coordinates 37.7749, -122.4194.
"""

# Get PII entities from the text
output = gen(text, aggregation_strategy="first")

# Clean and structure the data for JSON serialization
cleaned_output = []

for entity in output:
    cleaned_entity = {
        "entity": entity["word"],
        "label": entity["entity_group"],
        "score": round(entity["score"], 4),
        "start": entity["start"],
        "end": entity["end"]
    }
    print(entity)
    cleaned_output.append(cleaned_entity)

