#!/usr/bin/env python3
#
# pii_extraction.py

from transformers import pipeline
import re

model = "ab-ai/pii_model_based_on_distilbert"
model = "ab-ai/pii_model"
model = "lakshyakh93/deberta_finetuned_pii"

from transformers import pipeline
import re

# Initialize the PII detection pipeline
pipe = pipeline("token-classification", model=model)

text = """
Overview of Digital Identifiers and Security
In today's digital world, managing and protecting personal and sensitive information is essential. Below is a concise overview of various identifiers and security measures with examples.

Identification Numbers
AADHAAR: A 12-digit number (e.g., 123412341234).
Australian ABN: An 11-digit identifier (e.g., 12345678901).
Brazilian CPF: An 11-digit number (e.g., 123.456.789-09).
National ID (China): An 18-digit number (e.g., 123456789012345678).
Financial Information
Bank Account: Account number (e.g., 12345678901234).
Credit Card: 16-digit number (e.g., 4111-1111-1111-1111).
IBAN: International account number (e.g., GB33BUKB20201555555555).
SWIFT: Bank code (e.g., DEUTDEFF).
Personal Information
Full Name: John Michael Doe.
Date of Birth: 01/23/1985.
Email: john.doe@example.com.
Phone Number: +1-123-456-7890.
Security Information
Password: P@ssw0rd123!.
Security Question: "First pet's name?"
License Key: ABCD-EFGH-IJKL-MNOP.
Student ID: STU123456.
Travel Documents
Passport: 9-digit number (e.g., 123456789).
Issue Date: 01/01/2020.
Expiration Date: 01/01/2030.
Technical Identifiers
MAC Address: 00:1A:2B:3C:4D:5E.
IPv4 Address: 192.168.1.1.
IPv6 Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
"""


# Predict entities using the PII detection model
model_entities = pipe(text)

# Reconstruct entities from the model output
reconstructed_entities = []
current_entity = None
current_label = None

for entity in model_entities:
    word = entity['word'].replace("##", "")  # Handle subword tokens
    label = entity['entity'].split('-')[-1]  # Get the label (ignore B- or I- prefix)

    if current_label is None:  # Starting a new entity
        current_entity = word
        current_label = label
    elif label == current_label:  # Continue the current entity
        current_entity += word
    else:  # Finish the current entity and start a new one
        reconstructed_entities.append({"text": current_entity, "label": current_label})
        current_entity = word
        current_label = label

# Add the last entity
if current_entity:
    reconstructed_entities.append({"text": current_entity, "label": current_label})

# Define regex patterns for additional sensitive data extraction
def extract_sensitive_data(text):
    patterns = {
        "FULL_NAME": r"\b(?:Name:|Full Name:|First Name:|Last Name:|Middle Name:)\s*[A-Z][a-zA-Z]+( [A-Z][a-zA-Z]*)* [A-Z][a-zA-Z]+\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "CREDIT_CARD": r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b",
        "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "PHONE_US": r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "DOB": r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b|\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b",
        "MAC_ADDRESS": r"\b[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}\b",
        "IPV4": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "CATCHALL_ID": r"\b[A-Z0-9]{2,4}([-.\s]?[A-Z0-9]{2,5}){1,4}\b",
        # Add additional patterns here as needed
    }

    results = []

    for label, pattern in patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            results.append({"text": match.strip(), "label": label})

    return results

# Extract entities using regex patterns
regex_entities = extract_sensitive_data(text)

# Combine model and regex results
#combined_entities = reconstructed_entities + regex_entities
combined_entities = reconstructed_entities

# Print the results
for entity in combined_entities:
    print(entity["text"], "=>", entity["label"])

