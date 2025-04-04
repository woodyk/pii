#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: pii_extractor.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 15:01:37
#!/usr/bin/env python3
#
# pii_extractor.py

import spacy
import re
from spacy.matcher import Matcher
import nltk
from nltk import word_tokenize, pos_tag, ne_chunk
from nltk.corpus import stopwords
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
import json

# Load SpaCy model
nlp = spacy.load("en_core_web_sm")

# Download necessary NLTK data files
nltk.download('punkt')
nltk.download('maxent_ne_chunker')
nltk.download('words')
nltk.download('averaged_perceptron_tagger')

class PIIExtractor:
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        self.matcher = Matcher(nlp.vocab)

        # Define custom patterns for PII
        ipv4_pattern = [
            [{"TEXT": {"REGEX": r"(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?"}}]
        ]
        self.matcher.add("IPV4_ADDRESS", ipv4_pattern)

        ipv6_patterns = [
            [{"TEXT": {"REGEX": r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?"}}],
            [{"TEXT": {"REGEX": r"([0-9a-fA-F]{1,4}:){1,7}:([0-9a-fA-F]{1,4})?(\/\d{1,3})?"}}]
        ]
        self.matcher.add("IPV6_ADDRESS", ipv6_patterns)

        geo_coord_pattern = [
            [{"TEXT": {"REGEX": r"-?\d{1,3}\.\d+"}}, {"TEXT": {"REGEX": r",\s?"}}, {"TEXT": {"REGEX": r"-?\d{1,3}\.\d+"}}]
        ]
        self.matcher.add("GEO_COORDINATE", geo_coord_pattern)

    def extract_pii(self, text):
        """Extract PII from a given text using SpaCy and custom patterns."""
        doc = nlp(text)

        extracted_pii = {
            'names': self.extract_names(doc),
            'emails': self.extract_emails(doc),
            'phone_numbers': self.extract_phone_numbers(doc),
            'ssns': self.extract_ssns(doc),
            'credit_cards': self.extract_credit_cards(doc),
            'date_times': self.extract_dates(doc),
            'bank_accounts': self.extract_bank_accounts(doc),
            'routing_numbers': self.extract_routing_numbers(doc),
            'vin_numbers': self.extract_vin_numbers(doc),
            'drivers_licenses': self.extract_drivers_licenses(doc),
            'urls': self.extract_urls(doc),
            'ipv4_addresses': self.extract_ipv4_addresses(doc),
            'ipv6_addresses': self.extract_ipv6_addresses(doc),
            'geo_coordinates': self.extract_geo_coordinates(doc),
            'addresses': self.extract_addresses(doc)
        }

        return extracted_pii

    def extract_names(self, doc):
        """Extract names using SpaCy's NER."""
        nltk_names = [ent.text for ent in doc.ents if ent.label_ == "PERSON" and ent.text.lower() not in self.stop_words]
        return list(set(nltk_names))

    def extract_emails(self, doc):
        """Extract emails using SpaCy."""
        spacy_emails = [token.text for token in doc if token.like_email]
        return list(set(spacy_emails))

    def extract_phone_numbers(self, doc):
        """Extract phone numbers using SpaCy."""
        spacy_phones = [token.text for token in doc if token.like_num and len(token.text) >= 10]
        return list(set(spacy_phones))

    def extract_ssns(self, doc):
        ssns = []
        for token in doc:
            if token.text.isdigit() and len(token.text) == 3:
                next_token = token.nbor(1)
                next_next_token = next_token.nbor(1) if next_token else None
                if next_token and next_token.text == "-" and next_next_token and next_next_token.text.isdigit() and len(next_next_token.text) == 2:
                    third_token = next_next_token.nbor(1)
                    if third_token and third_token.text == "-" and third_token.nbor(1).text.isdigit() and len(third_token.nbor(1).text) == 4:
                        ssn = f"{token.text}-{next_next_token.text}-{third_token.nbor(1).text}"
                        ssns.append(ssn)
        return ssns

    def extract_credit_cards(self, doc):
        """Extract credit cards using SpaCy."""
        spacy_cards = []
        for token in doc:
            if token.like_num and len(token.text) == 4:
                sequence = [token.text]
                for i in range(3):
                    next_token = token.nbor(i + 1)
                    if next_token and next_token.like_num and len(next_token.text) == 4:
                        sequence.append(next_token.text)
                    else:
                        break
                if len(sequence) == 4:
                    spacy_cards.append(" ".join(sequence))
        return list(set(spacy_cards))

    def extract_dates(self, doc):
        """Extract dates using SpaCy."""
        spacy_dates = [ent.text for ent in doc.ents if ent.label_ == "DATE" or ent.label_ == "TIME"]
        return list(set(spacy_dates))

    def extract_bank_accounts(self, doc):
        """Extract bank accounts using SpaCy."""
        spacy_accounts = [token.text for token in doc if token.like_num and 9 <= len(token.text) <= 12]
        return list(set(spacy_accounts))

    def extract_routing_numbers(self, doc):
        routing_numbers = [token.text for token in doc if token.like_num and len(token.text) == 9]
        return routing_numbers

    def extract_vin_numbers(self, doc):
        vin_numbers = [token.text for token in doc if len(token.text) == 17 and token.text.isalnum()]
        return vin_numbers

    def extract_drivers_licenses(self, doc):
        """Extract driver's licenses using custom patterns."""
        matches = self.matcher(doc, as_spans=True)
        spacy_licenses = [span.text for span in matches if span.label_ == "DRIVERS_LICENSE"]
        return list(set(spacy_licenses))

    def extract_urls(self, doc):
        urls = [token.text for token in doc if token.like_url]
        return urls

    def extract_ipv4_addresses(self, doc):
        matches = self.matcher(doc, as_spans=True)
        ipv4_addresses = [span.text for span in matches if span.label_ == "IPV4_ADDRESS"]
        return ipv4_addresses

    def extract_ipv6_addresses(self, doc):
        matches = self.matcher(doc, as_spans=True)
        ipv6_addresses = [span.text for span in matches if span.label_ == "IPV6_ADDRESS"]
        return ipv6_addresses

    def extract_geo_coordinates(self, doc):
        matches = self.matcher(doc, as_spans=True)
        geo_coordinates = [span.text for span in matches if span.label_ == "GEO_COORDINATE"]
        return geo_coordinates

    def extract_addresses(self, doc):
        """Extract addresses using SpaCy and regex patterns for international formats."""
        spacy_addresses = []
        for ent in doc.ents:
            if ent.label_ in {"GPE", "LOC", "FAC", "ADDRESS"}:  # Geopolitical Entity, Location, Facility
                spacy_addresses.append(ent.text)
            elif ent.label_ == "ORG" and any(substring in ent.text for substring in ["Street", "St", "Ave", "Road", "Blvd", "Drive"]):
                spacy_addresses.append(ent.text)

        # Additional pattern matching for common international and US address patterns
        address_patterns = [
            r'\d{1,5}\s\w+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Square|Sq|Trail|Trl|Parkway|Pkwy|Commons|Cmns)\s\S+\s\S+',  # US addresses
            r'\d{1,5}\s\w+\s(?:Str|Straße|Straße)\s\S+\s\S+',  # German-style addresses
            r'\d{1,5}\s\w+\s(?:Rue|Boulevard|Bd|Avenue|Av)\s\S+\s\S+',  # French-style addresses
            r'\d{1,5}\s\w+\s(?:Via|Piazza|Corso|Largo)\s\S+\s\S+',  # Italian-style addresses
            r'\d{1,5}\s\w+\s(?:Calle|Carrera|Avenida|Av)\s\S+\s\S+',  # Spanish-style addresses
            r'\d{1,5}\s\w+\s(?:Street|Avenue|Rd|Drive|Blvd)\s\S+',  # Generic address pattern
            r'[A-Z]{1,2}\d{1,2}\s\d{1,2}[A-Z]{1,2}',  # UK postal codes
            r'\d{3}-\d{4}',  # Japanese postal codes
            r'\d{4}',  # Simplified postal code (e.g., many European countries)
        ]

        regex_addresses = []
        for pattern in address_patterns:
            regex_addresses.extend(re.findall(pattern, doc.text))

        return list(set(spacy_addresses + regex_addresses))

# Example usage:
if __name__ == "__main__":
    text = """
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

    extractor = PIIExtractor()
    pii_data = extractor.extract_pii(text)

    print(json.dumps(pii_data, indent=4))
