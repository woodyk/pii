#!/usr/bin/env python3
#
# spacy_pii.py

import scrubadub
import scrubadub.filth

# Define the text containing various types of PII
text = """
My name is John Doe, my phone number is (123) 456-7890, and my email is john.doe@example.com.
My Social Security Number is 123-45-6789. My credit card number is 4111-1111-1111-1111.
"""

# Add custom filth detectors if needed, scrubadub has a credit card detector by default
# scrubadub's default detectors already include Phone, Email, Name, and Credit Card Filth

# Clean the text to remove PII
cleaned_text = scrubadub.clean(text)

print(cleaned_text)

