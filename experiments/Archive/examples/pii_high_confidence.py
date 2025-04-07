#!/usr/bin/env python3
#
# pii_high_confidence.py

import re
import spacy
import json
nlp = spacy.load("en_core_web_sm")

def extract_ipv4_and_cidr(text):
    # Regular expression for matching IPv4 addresses (0-255 in each octet)
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    # Regular expression for matching IPv4 CIDR blocks (IPv4 address + / + subnet mask)
    cidr_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:[0-9]|[12][0-9]|3[0-2])\b'

    # Function to validate that the IPv4 parts are within 0-255 range
    def validate_ipv4(ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    # Extract all IPv4 addresses
    ipv4_matches = re.findall(ipv4_pattern, text)
    ipv4_addresses = [ip for ip in ipv4_matches if validate_ipv4(ip)]

    # Extract all CIDR blocks
    cidr_matches = re.findall(cidr_pattern, text)
    cidr_blocks = [cidr for cidr in cidr_matches if validate_ipv4(cidr.split('/')[0])]

    return {"ipv4_addresses": ipv4_addresses, "cidr_blocks": cidr_blocks}

def extract_ipv6_and_cidr(text):
    # Regular expression to match full or shortened IPv6 addresses
    ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}\b'

    # Regular expression to match IPv6 CIDR blocks (IPv6 address + / + subnet mask 0-128)
    cidr_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\b|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\b'

    # Extract IPv6 addresses
    ipv6_matches = re.findall(ipv6_pattern, text)

    # Extract IPv6 CIDR blocks
    cidr_matches = re.findall(cidr_pattern, text)

    return {"ipv6_addresses": ipv6_matches, "cidr_blocks": cidr_matches}

def extract_urls(text):
    # Regular expression pattern for matching URLs with various schemes (http, https, ftp, etc.)
    url_pattern = re.compile(
        r'\b(?:https?|ftp|ftps|file|mailto|data|irc|ssh|telnet|ldap|news|nntp)://'
        r'(?:[a-zA-Z0-9\-._~%!$&\'()*+,;=:]+@)?'  # Optional userinfo (username:password)
        r'(?:[a-zA-Z0-9\-._~%]+|\[[a-fA-F0-9:.]+\])'  # Hostname or IPv6 address
        r'(?::\d+)?'  # Optional port number
        r'(?:/[a-zA-Z0-9\-._~%!$&\'()*+,;=:@/]*)*'  # Path
        r'(?:\?[a-zA-Z0-9\-._~%!$&\'()*+,;=:@/?]*)?'  # Query string
        r'(?:#[a-zA-Z0-9\-._~%!$&\'()*+,;=:@/?]*)?'  # Fragment identifier
    )

    # Find all URLs in the text
    urls = re.findall(url_pattern, text)

    return urls

def extract_geo_coordinates(text):
    doc = nlp(text)

    # Regular expression to match decimal degree coordinates (latitude, longitude)
    decimal_pattern = r'\b(-?[1-8]?\d(\.\d+)?|90(\.0+)?),\s*(-?(1[0-7]\d(\.\d+)?|180(\.0+)?|[1-9]?\d(\.\d+)?))\b'

    # Regular expression to match degrees, minutes, and seconds (DMS) format
    dms_pattern = r'\b(\d{1,3})°\s*(\d{1,2})\'\s*(\d{1,2}(?:\.\d+)?)?"?\s*([NSEW]),?\s*(\d{1,3})°\s*(\d{1,2})\'\s*(\d{1,2}(?:\.\d+)?)?"?\s*([NSEW])\b'

    # Helper function to validate and check if lat/lon values are within valid range
    def validate_lat_lon(lat, lon):
        try:
            lat = float(lat)
            lon = float(lon)
            return -90 <= lat <= 90 and -180 <= lon <= 180
        except ValueError:
            return False

    # Extract decimal coordinates using regex
    decimal_matches = re.findall(decimal_pattern, text)
    decimal_coords = [(float(lat), float(lon)) for lat, lon, *_ in decimal_matches if validate_lat_lon(lat, lon)]

    # Extract DMS coordinates using regex and convert them to decimal format
    dms_matches = re.findall(dms_pattern, text)

    def dms_to_decimal(degrees, minutes, seconds, direction):
        decimal = float(degrees) + float(minutes) / 60 + (float(seconds) if seconds else 0) / 3600
        if direction in ['S', 'W']:
            decimal *= -1
        return decimal

    dms_coords = []
    for dms in dms_matches:
        lat_deg, lat_min, lat_sec, lat_dir, lon_deg, lon_min, lon_sec, lon_dir = dms
        lat = dms_to_decimal(lat_deg, lat_min, lat_sec, lat_dir)
        lon = dms_to_decimal(lon_deg, lon_min, lon_sec, lon_dir)
        if validate_lat_lon(lat, lon):
            dms_coords.append((lat, lon))

    # Extract named places using spaCy's NER
    places = [ent.text for ent in doc.ents if ent.label_ in ["GPE", "LOC"]]  # GPE = Geo-political entity, LOC = Location

    # Combine all extracted coordinates
    all_coords = decimal_coords + dms_coords

    return {"coordinates": all_coords, "places": places}

def extract_postal_codes(text):
    """
    Extract postal codes from text for various countries and validate their format
    based on country-specific rules.
    """

    def validate_postal_code(code):
        """
        Additional country-specific validation for postal codes based on rules and structure.
        """

        # USA: Validate length and known ZIP code ranges (00000 is invalid)
        if re.match(r'^\d{5}(?:-\d{4})?$', code):
            if code.startswith("00"):
                return False  # Invalid ZIP range
            return True

        # Canada: Ensure the postal code matches the proper format (A1A 1A1)
        if re.match(r'^[ABCEGHJKLMNPRSTVXY]\d[ABCEGHJKLMNPRSTVWXYZ] \d[ABCEGHJKLMNPRSTVWXYZ]\d$', code):
            return True

        # UK: Ensure valid postal code format (SW1A 1AA, W1A 0AX)
        if re.match(r'^[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}$', code):
            return True

        # Germany and France: Validate as a 5-digit postal code
        if re.match(r'^\d{5}$', code):
            return True

        # Australia: Validate as a 4-digit postal code
        if re.match(r'^\d{4}$', code):
            return True

        return False

    # Define regex patterns for different countries' postal codes

    # USA: ZIP code (5 digits or ZIP+4 format)
    usa_pattern = r'\b\d{5}(?:-\d{4})?\b'

    # Canada: Alphanumeric postal code (e.g., A1A 1A1 or A1A-1A1)
    canada_pattern = r'\b[ABCEGHJKLMNPRSTVXY]\d[ABCEGHJKLMNPRSTVWXYZ](?:[- ]?\d[ABCEGHJKLMNPRSTVWXYZ]\d)\b'

    # UK: Multiple alphanumeric formats (e.g., SW1A 1AA, W1A 0AX)
    uk_pattern = r'\b[A-Z]{1,2}\d{1,2}[A-Z]?(?:\s*\d[A-Z]{2})\b'

    # Combine all patterns into one regex pattern
    postal_code_patterns = f'({usa_pattern})|({canada_pattern})|({uk_pattern})'

    # Find all matches in the text
    postal_codes = re.findall(postal_code_patterns, text)

    # Flatten the list of tuples into a list of postal codes
    extracted_codes = [code for match in postal_codes for code in match if code]

    # Apply additional validation rules for specific countries
    valid_codes = [code for code in extracted_codes if validate_postal_code(code)]

    return valid_codes

def extract_vin_numbers(text):
    """
    Extract and validate VIN numbers from the given text based on the standard 17-character VIN format.
    Includes check digit validation.
    """

    def calculate_vin_check_digit(vin):
        """
        Calculate and validate the VIN check digit (9th position).
        Uses the weighted sum and modulo 11 rules for check digit validation.
        """
        vin_weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
        vin_translations = {
            'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8, 'J': 1, 'K': 2, 'L': 3,
            'M': 4, 'N': 5, 'P': 7, 'R': 9, 'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
            '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9
        }

        # Calculate the weighted sum
        total_sum = 0
        for i in range(17):
            char = vin[i]
            value = vin_translations[char]
            weight = vin_weights[i]
            total_sum += value * weight

        # Calculate the check digit
        remainder = total_sum % 11
        if remainder == 10:
            return 'X'  # Special case: if remainder is 10, the check digit is 'X'
        else:
            return str(remainder)

    def validate_vin(vin):
        """
        Validate the VIN by checking its length and verifying the check digit.
        """
        # VIN must be 17 characters long
        if len(vin) != 17:
            return False

        # Validate the check digit (9th character)
        expected_check_digit = calculate_vin_check_digit(vin)
        actual_check_digit = vin[8]  # 9th position is at index 8
        return expected_check_digit == actual_check_digit

    # Define regex pattern for VIN (17 characters, no I, O, or Q)
    vin_pattern = r'\b[A-HJ-NPR-Z0-9]{17}\b'

    # Find all VIN matches in the text
    vin_numbers = re.findall(vin_pattern, text)

    # Filter the results to only include valid VINs based on the check digit
    valid_vins = [vin for vin in vin_numbers if validate_vin(vin)]

    return valid_vins

def extract_mac_addresses(text):
    # Define regex patterns for MAC addresses
    # Colon or hyphen-separated MAC addresses (e.g., 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E)
    mac_pattern_colon_hyphen = r'\b([A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2}\b'

    # Dot-separated MAC addresses (e.g., 001A.2B3C.4D5E)
    mac_pattern_dot = r'\b([A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}\b'

    # Combine both patterns into one regex pattern
    mac_pattern = f'({mac_pattern_colon_hyphen})|({mac_pattern_dot})'

    # Find all matches in the text
    mac_addresses = re.findall(mac_pattern, text)

    # Flatten the list of tuples into a list of valid MAC addresses
    extracted_macs = [mac[0] if mac[0] else mac[2] for mac in mac_addresses]

    return extracted_macs

def extract_routing_numbers(text):
    """
    Extract and validate routing numbers from the given text.
    A valid routing number is 9 digits long and passes the checksum validation.
    """
    # Regular expression to find 9-digit sequences in the text
    routing_pattern = r'\b\d{9}\b'

    # Find all potential routing numbers
    potential_routing_numbers = re.findall(routing_pattern, text)

    # Checksum validation within the same function
    valid_routing_numbers = []
    for routing_number in potential_routing_numbers:
        if len(routing_number) == 9 and routing_number.isdigit():
            # Apply the checksum formula
            total = (3 * (int(routing_number[0]) + int(routing_number[3]) + int(routing_number[6])) +
                     7 * (int(routing_number[1]) + int(routing_number[4]) + int(routing_number[7])) +
                     1 * (int(routing_number[2]) + int(routing_number[5]) + int(routing_number[8])))
            if total % 10 == 0:
                valid_routing_numbers.append(routing_number)

    return valid_routing_numbers

def extract_bank_account_numbers(text):
    """
    Extract bank account numbers based on common country formats.
    Includes support for IBAN and generic digit-based account numbers (US, UK, etc.).
    """

    # IBAN format: up to 34 alphanumeric characters (letters and digits), country-specific length
    iban_pattern = r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b'

    # USA bank account numbers: Typically 5 to 17 digits
    usa_pattern = r'\b\d{5,17}\b'

    # UK bank account numbers: Sort code + 8 digits (e.g., 12-34-56 12345678)
    uk_pattern = r'\b\d{2}-\d{2}-\d{2} \d{8}\b'

    # Canada: Typically 7 to 12 digits
    canada_pattern = r'\b\d{7,12}\b'

    # Australia: Typically 9 digits
    australia_pattern = r'\b\d{9}\b'

    # India: 9 to 18 digits, depending on the bank
    india_pattern = r'\b\d{9,18}\b'

    # Combine all patterns into one regex pattern
    account_patterns = f'({iban_pattern})|({usa_pattern})|({uk_pattern})|({canada_pattern})|({australia_pattern})|({india_pattern})'

    # Find all potential bank account numbers in the text
    potential_account_numbers = re.findall(account_patterns, text)

    # Flatten the list of tuples into a list of account numbers, removing empty matches
    extracted_accounts = [account for match in potential_account_numbers for account in match if account]

    return extracted_accounts

def extract_credit_card_numbers(text):
    """
    Extract and validate credit card numbers from text based on common card issuer formats.
    """

    def luhn_algorithm(card_number):
        """
        Validate credit card number using the Luhn algorithm.
        """
        digits = [int(digit) for digit in card_number]
        checksum = 0

        # Double every second digit from the right, subtract 9 if greater than 9
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit

        return checksum % 10 == 0

    # Regular expression to find 13 to 19 digits (with optional spaces or hyphens in between)
    card_pattern = r'\b(?:\d[ -]*?){13,19}\b'

    # Find all potential credit card numbers
    potential_card_numbers = re.findall(card_pattern, text)

    # Clean up the numbers by removing spaces and hyphens, and validate using Luhn algorithm
    valid_card_numbers = []
    for card in potential_card_numbers:
        cleaned_card = re.sub(r'[ -]', '', card)  # Remove spaces and hyphens
        if 13 <= len(cleaned_card) <= 19 and luhn_algorithm(cleaned_card):
            valid_card_numbers.append(cleaned_card)

    return valid_card_numbers

def extract_social_security_numbers(text):
    """
    Extract and validate Social Security Numbers (SSNs) from text.
    Valid formats include XXX-XX-XXXX or XXXXXXXXX.
    """

    # Regular expression to match SSN formats: XXX-XX-XXXX or XXXXXXXXX
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'

    # Find all potential SSNs
    potential_ssns = re.findall(ssn_pattern, text)

    # Validate that no part of the SSN is all zeros
    valid_ssns = []
    for ssn in potential_ssns:
        # Clean SSN by removing hyphens for uniform validation
        cleaned_ssn = ssn.replace('-', '')

        # SSN cannot have all zeros in any section (e.g., 000-XX-XXXX is invalid)
        if not (cleaned_ssn[:3] == '000' or cleaned_ssn[3:5] == '00' or cleaned_ssn[5:] == '0000'):
            valid_ssns.append(ssn)

    return valid_ssns

def extract_email_addresses(text):
    """
    Extract valid email addresses from the given text based on standard email address formats.
    This version ensures no consecutive dots in the domain and local parts.
    """

    # Regular expression for matching valid email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    # Find all potential email addresses in the text
    potential_emails = re.findall(email_pattern, text)

    # Validate email addresses to remove any with consecutive dots in the domain part
    valid_emails = []
    for email in potential_emails:
        # Split the email into local part and domain part
        local_part, domain_part = email.split('@')

        # Check if there are consecutive dots in the local or domain parts, which are invalid
        if '..' not in local_part and '..' not in domain_part:
            valid_emails.append(email)

    return valid_emails

def extract_phone_numbers(text):
    """
    Extract and validate phone numbers from the given text based on common phone number formats.
    This version handles optional country codes, area codes, and different separators.
    It also strips any leading or trailing whitespace from the results.
    """

    def validate_phone_number(number):
        """
        Validate the phone number based on E.164 format and ensure it has a valid length and structure.
        E.164 allows a maximum of 15 digits including the country code.
        """
        # Remove all non-digit characters for validation
        cleaned_number = re.sub(r'\D', '', number)

        # E.164 phone numbers must be between 10 and 15 digits
        if 10 <= len(cleaned_number) <= 15:
            return True
        return False

    # Regular expression for matching phone numbers (domestic and international formats)
    phone_pattern = r'''
        # Match optional country code, area code, and various separators
        (?:(?:\+?\d{1,3})?        # Optional country code, e.g., +1 or +44
        [\s.-]?)?                 # Optional separator after country code
        (?:\(?\d{3}\)?            # Area code, e.g., (123) or 123
        [\s.-]?)?                 # Optional separator after area code
        \d{3}                     # First 3 digits
        [\s.-]?                   # Optional separator
        \d{4}                     # Last 4 digits
    '''
    
    # Compile the pattern with re.VERBOSE for better readability
    phone_regex = re.compile(phone_pattern, re.VERBOSE)

    # Find all potential phone numbers
    potential_phone_numbers = phone_regex.findall(text)
    
    # Strip whitespace, validate and filter phone numbers based on length and format
    valid_phone_numbers = [num.strip() for num in potential_phone_numbers if validate_phone_number(num.strip())]

    return valid_phone_numbers

def extract_date_time(text):
    """
    Extract date and time strings from the given text based on common formats.
    Handles various date and time formats (ISO, US, European, 24-hour, 12-hour with AM/PM).
    """

    # Regular expression for matching dates in various formats
    date_pattern = r'''
        # ISO date format (YYYY-MM-DD or YYYY/MM/DD)
        (\b\d{4}[-/]\d{2}[-/]\d{2}\b) |
        # US date format (MM/DD/YYYY or MM-DD-YYYY)
        (\b\d{2}[-/]\d{2}[-/]\d{4}\b) |
        # European date format (DD/MM/YYYY or DD-MM-YYYY)
        (\b\d{2}[-/]\d{2}[-/]\d{4}\b) |
        # Date with month names (e.g., 12 March 2023)
        (\b\d{1,2} (January|February|March|April|May|June|July|August|September|October|November|December) \d{4}\b)
    '''

    # Regular expression for matching times in various formats
    time_pattern = r'''
        # 24-hour time format (HH:MM or HH:MM:SS)
        (\b\d{1,2}:\d{2}(?::\d{2})?\b) |
        # 12-hour time format with AM/PM (HH:MM AM/PM)
        (\b\d{1,2}:\d{2}\s?(AM|PM|am|pm)\b)
    '''

    # Compile the patterns using re.VERBOSE to allow comments and multi-line strings
    date_regex = re.compile(date_pattern, re.VERBOSE)
    time_regex = re.compile(time_pattern, re.VERBOSE)

    # Extract dates and times separately
    potential_dates = date_regex.findall(text)
    potential_times = time_regex.findall(text)

    # Flatten the lists and filter out empty matches
    extracted_dates = [date for match in potential_dates for date in match if date]
    extracted_times = [time for match in potential_times for time in match if time]

    return extracted_dates, extracted_times

def extract_passport_numbers(text):
    """
    Extract passport numbers based on common country formats.
    Passport numbers typically consist of 6 to 9 alphanumeric characters.
    """

    # USA: 9 digits (e.g., 123456789)
    usa_pattern = r'\b\d{9}\b'

    # UK: 9 alphanumeric characters (e.g., 123456789 or A12345678)
    uk_pattern = r'\b[A-Z0-9]{9}\b'

    # Canada: 8 characters, starts with a letter (e.g., A1234567)
    canada_pattern = r'\b[A-Z]\d{7}\b'

    # India: 8 alphanumeric characters (e.g., A1234567)
    india_pattern = r'\b[A-Z]\d{7}\b'

    # Australia: 8 or 9 alphanumeric characters
    australia_pattern = r'\b[A-Z0-9]{8,9}\b'

    # Germany: 9 alphanumeric characters (e.g., C01X00T00)
    germany_pattern = r'\b[A-Z0-9]{9}\b'

    # France: 9 digits (e.g., 12 3456789)
    france_pattern = r'\b\d{2}\s?\d{7}\b'

    # Combine all patterns into one regex pattern
    passport_patterns = f'({usa_pattern})|({uk_pattern})|({canada_pattern})|({india_pattern})|({australia_pattern})|({germany_pattern})|({france_pattern})'

    # Find all potential passport numbers in the text
    potential_passport_numbers = re.findall(passport_patterns, text)

    # Flatten the list of tuples into a list of passport numbers
    extracted_passports = [passport for match in potential_passport_numbers for passport in match if passport]

    return extracted_passports

def extract_swift_codes(text):
    # Complete list of ISO 3166-1 alpha-2 country codes
    ISO_COUNTRY_CODES = {
        "AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", 
        "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", 
        "BV", "BR", "IO", "BN", "BG", "BF", "BI", "CV", "KH", "CM", "CA", "KY", "CF", "TD", "CL", 
        "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CU", "CW", "CY", "CZ", 
        "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "ER", "EE", "SZ", "ET", "FK", "FO", "FJ", 
        "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP", 
        "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "HN", "HK", "HU", "IS", "IN", "ID", "IR", 
        "IQ", "IE", "IM", "IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", 
        "KG", "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MG", "MW", "MY", "MV", 
        "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", 
        "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MK", "MP", 
        "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA", 
        "RE", "RO", "RU", "RW", "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", 
        "SN", "RS", "SC", "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES", "LK", 
        "SD", "SR", "SJ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", 
        "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", 
        "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW"
    }

    # Helper function to validate a SWIFT code
    def validate_swift_code(swift_code):
        # Length check: must be 8 or 11 characters long
        if len(swift_code) not in [8, 11]:
            return False
        
        # Check bank code (first 4 characters must be alphabetic)
        bank_code = swift_code[:4]
        if not bank_code.isalpha():
            return False
        
        # Check country code (next 2 characters must be a valid ISO country code)
        country_code = swift_code[4:6]
        if country_code not in ISO_COUNTRY_CODES:
            return False
        
        # Check location code (next 2 characters must be alphanumeric)
        location_code = swift_code[6:8]
        if not location_code.isalnum():
            return False
        
        # If the code is 11 characters, check the branch code (must be alphanumeric)
        if len(swift_code) == 11:
            branch_code = swift_code[8:]
            if not branch_code.isalnum():
                return False
        
        return True

    # Regular expression to match possible SWIFT codes (8 or 11 alphanumeric characters)
    swift_code_pattern = r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'
    
    # Find all potential SWIFT codes in the text
    potential_swift_codes = re.findall(swift_code_pattern, text)
    
    # Validate each found code and return only the valid ones
    valid_swift_codes = [code for code in potential_swift_codes if validate_swift_code(code)]
    
    return valid_swift_codes

def extract_all_from_text(text):
    """
    This function dynamically calls all functions that start with 'extract_' and aggregates
    their results into a single JSON-compatible dictionary.
    """

    # Dictionary to hold the results
    extracted_data = {}

    # Iterate over all functions in the current global namespace
    for name, func in globals().items():
        # Check if the function name starts with 'extract_' but exclude this function itself and ensure it's callable
        if name.startswith("extract_") and name != "extract_all_from_text" and callable(func):
            try:
                # Call the function with the provided text and store the result
                result = func(text)
                extracted_data[name] = result
            except Exception as e:
                # Handle any exceptions that might occur when calling the function
                extracted_data[name] = f"Error: {str(e)}"

    return extracted_data

# Example usage
text = """
Here are examples of various data types:

1. **IP Addresses**:
   IPv4: 192.168.1.1, 255.255.255.255, 10.0.0.1, 192.168.0.0/16, 127.0.0.1
   IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334, fe80::1, 2001:db8::/48

2. **URLs**:
   http://example.com, https://secure-site.org, ftp://ftp.example.com, mailto:user@example.com

3. **Email addresses**:
   user@example.com, another.user@domain.org, test123+filter@sub.domain.com

4. **Phone numbers**:
   +1 (123) 456-7890, 123-456-7890, 5555555555, +44 20 7946 0958, +91-9876543210

5. **Dates and times**:
   ISO date: 2023-09-01, 2023/09/01
   US date: 09/01/2023, 09-01-2023
   European date: 01/09/2023, 01-09-2023
   Date with month: 15 March 2023, 7 July 2021
   Times: 14:30, 09:45:30, 3:45 PM, 12:00 AM

6. **Postal codes**:
   USA: 12345, 90210-1234
   Canada: A1A 1A1, B2B-2B2
   UK: SW1A 1AA, EC1A 1BB
   Germany: 10115, France: 75008, Australia: 2000

7. **VIN numbers**:
   1HGCM82633A123456, JH4KA4650MC000000, 5YJSA1CN5DFP01234

8. **MAC addresses**:
   00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E, 001A.2B3C.4D5E

9. **Routing numbers**:
   011000015, 121000358, 123456789 (Invalid), 021000021

10. **Bank account numbers**:
    IBAN: DE44 5001 0517 5407 3249 31, GB29 NWBK 6016 1331 9268 19
    US: 12345678901234567, 987654321

11. **Credit card numbers**:
    4111 1111 1111 1111 (Visa), 5500-0000-0000-0004 (MasterCard), 378282246310005 (American Express), 6011 1111 1111 1117 (Discover)

12. **Social Security Numbers (SSNs)**:
    123-45-6789, 987654321, 000-12-3456 (Invalid)

13. **Passport numbers**:
    USA: 123456789, UK: 987654321, Canada: A1234567, India: B9876543

14. **SWIFT codes**:
    BOFAUS3NXXX, CHASUS33, DEUTDEFF500, HSBCGB2LXXX

15. **Geo-coordinates**:
    Decimal: 37.7749, -122.4194; 40.7128, -74.0060
    Degrees, minutes, seconds: 40°42'51"N 74°00'21"W, 37°46'29"N 122°25'09"W

1HGCM82633A004352, JH4TB2H26CC000000, 5YJSA1CN5DFP01234
"""

extracted_data = extract_all_from_text(text)
print(json.dumps(extracted_data, indent=4))

