#!/usr/bin/env python3
#
# re_detection.py

import re
import json
from collections import OrderedDict

# Regex building functions
def build_regex_patterns():
    return {
        "DATETIME": {
            # Date Patterns
            "numeric_date": r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
            "year_first_date": r'\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b',
            "textual_date": r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b',
            "ordinal_date": r'\b\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*,?\s+\d{4}\b',
            "weekday_date": r'\b(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)[a-z]*,\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b',
            # Time Patterns
            "twelve_hour_time": r'\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?\b',
            "twenty_four_hour_time": r'\b\d{1,2}:\d{2}(:\d{2})?\b',
            "time_with_timezone": r'\b\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?\s*[A-Z]{2,4}\b',
            "iso_time_with_timezone": r'\b\d{2}:\d{2}:\d{2}[-+]\d{2}:\d{2}\b',
            # Combined Date and Time
            "datetime_numeric": r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\s+\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?\b',
            "datetime_iso": r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(?:Z|[-+]\d{2}:\d{2})?\b',
        },
        "GEO_COORDINATES": {
            "decimal_degrees": r'\b[+-]?\d{1,3}\.\d{4,},\s?[+-]?\d{1,3}\.\d{4,}\b',
            "decimal_degrees_direction": r'\b\d{1,3}\.\d{4,}[NS],\s?\d{1,3}\.\d{4,}[EW]\b',
            "dms_standard": r'\b\d{1,3}°\d{1,2}\'\d{1,2}(?:\.\d+)?["\']?[NS],\s?\d{1,3}°\d{1,2}\'\d{1,2}(?:\.\d+)?["\']?[EW]\b',
            "ddm_standard": r'\b\d{1,3}°\d{1,2}\.\d+\'[NS],\s?\d{1,3}°\d{1,2}\.\d+\'[EW]\b',
            "geo_uri": r'\bgeo:[+-]?\d{1,3}\.\d{4,},[+-]?\d{1,3}\.\d{4,}(?:,\d+)?\b',
        },
        "URL": {
            "url": r'\b\w+://\S+',
        },
        "LICENSE_PLATE": {
            "alphanumeric_3_3": r'\b[A-Z]{3}\d{3}\b',
            "alphanumeric_3_4": r'\b[A-Z]{3}\d{4}\b',
            "alphanumeric_2_2_2": r'\b[A-Z]{2}\d{2}[A-Z]{2}\b',
            "alphanumeric_3_digits": r'\b\d{3}[A-Z]{3}\b',
            "region_specific_1": r'\b[A-Z]{1,2} \d{1,4} [A-Z]{1,2}\b',
            "region_specific_2": r'\b[A-Z]{1,2}\d{1,4}[A-Z]{1,2}\b',
            "with_hyphens": r'\b[A-Z]{2}-\d{3}-[A-Z]{2}\b',
            "with_hyphen_end": r'\b[A-Z]{3}-\d{4}\b',
            "with_spaces": r'\b[A-Z]{3} \d{3}\b',
        },
        "POSTAL_CODE": {
            "numeric_5": r'\b\d{5}\b',
            "numeric_9": r'\b\d{5}-\d{4}\b',
            "alphanumeric_canada": r'\b[A-Za-z]\d[A-Za-z]\s?\d[A-Za-z]\d\b',
            "alphanumeric_uk": r'\b[A-Za-z]{1,2}\d{1,2}\s?\d[A-Za-z]{2}\b',
            "alphanumeric_netherlands": r'\b\d{4}\s?[A-Za-z]{2}\b',
            "alphanumeric_ireland": r'\b[A-Za-z]\d{2}\s?[A-Za-z]\d{2}\b',
            "alphanumeric_canada_nospace": r'\b[A-Za-z]\d[A-Za-z]\d[A-Za-z]\d\b',
            "alphanumeric_uk_nospace": r'\b[A-Za-z]{1,2}\d{1,2}[A-Za-z]{2}\b',
            "alphanumeric_netherlands_nospace": r'\b\d{4}[A-Za-z]{2}\b',
            "numeric_sweden": r'\b\d{3}\s\d{2}\b',
            "numeric_japan": r'\b\d{3}-\d{4}\b',
            "alphanumeric_ireland_special": r'\b[A-Za-z]{2}\d{2}\s\d[A-Za-z]{2}\b',
        },
        "VIN": {
            "standard_vin": r'\b[A-HJ-NPR-Z0-9]{17}\b',
            "vin_with_spaces": r'\b[A-HJ-NPR-Z0-9]{1,3}[\s][A-HJ-NPR-Z0-9]{1,3}[\s][A-HJ-NPR-Z0-9]{1,3}[\s][A-HJ-NPR-Z0-9]{1,3}[\s][A-HJ-NPR-Z0-9]{1,3}\b',
            "vin_with_hyphens": r'\b[A-HJ-NPR-Z0-9]{1,3}[-][A-HJ-NPR-Z0-9]{1,3}[-][A-HJ-NPR-Z0-9]{1,3}[-][A-HJ-NPR-Z0-9]{1,3}[-][A-HJ-NPR-Z0-9]{1,3}\b',
            "vin_with_dots": r'\b[A-HJ-NPR-Z0-9]{1,3}[.][A-HJ-NPR-Z0-9]{1,3}[.][A-HJ-NPR-Z0-9]{1,3}[.][A-HJ-NPR-Z0-9]{1,3}[.][A-HJ-NPR-Z0-9]{1,3}\b',
            "vin_mixed_separators": r'\b[A-HJ-NPR-Z0-9]{1,3}[-.\s][A-HJ-NPR-Z0-9]{1,3}[-.\s][A-HJ-NPR-Z0-9]{1,3}[-.\s][A-HJ-NPR-Z0-9]{1,3}[-.\s][A-HJ-NPR-Z0-9]{1,3}\b',
            "vin_with_obfuscation": r'\b[A-HJ-NPR-Z0-9Xx]{17}\b',
            "vin_with_special_chars": r'\b[A-HJ-NPR-Z0-9#@$%^&*]{17}\b',
        },
        "SWIFT_CODE": {
            "standard": r'b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b',
        },
        "IPV6_CIDR": {
            "standard_ipv6": r'(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}',
        },
        "IPV4_CIDR": {
            # Matches a standard IPv4 address (e.g., 192.168.0.1)
            "standard_ipv4": r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            # Matches a CIDR notation IPv4 address (e.g., 192.168.0.1/24)
            "cidr_block": r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/\d{1,2}\b',
        },
        "MAC_ADDRESS": {
            # Matches MAC addresses with colons or hyphens (e.g., 00:14:22:01:23:45 or 00-14-22-01-23-45)
            "delimited": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
            # Matches MAC addresses without any delimiters (e.g., 001422012345)
            "no_delimiter": r'\b[0-9A-Fa-f]{12}\b',
            # Matches MAC addresses in Cisco style (e.g., 001A.2B3C.4D5E)
            "cisco_style": r'\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b'
        },
        "DRIVERS_LICENSE": {
            "alphanumeric_1_letter_7_digits": r'\b[A-Z]\d{7}\b',
            "alphanumeric_2_letters_6_digits": r'\b[A-Z]{2}\d{6}\b',
            "alphanumeric_1_letter_8_digits": r'\b[A-Z]\d{8}\b',
            "alphanumeric_2_letters_7_digits": r'\b[A-Z]{2}\d{7}\b',
            "hyphenated_1_letter_3_4_digits": r'\b[A-Z]?\d{3}-\d{3}-\d{3,4}\b',
            "hyphenated_2_letters_4_digits": r'\b[A-Z]{2}\d{3}-\d{4}-\d{4}\b',
            "with_prefix_dl": r'\bDL:\s?[A-Z\d]+\b',
            "with_prefix_license_number": r'\bLicence\sNumber:\s?[A-Z\d]+\b',
            "generic_alphanumeric_specific": r'\b[A-Z]{1,2}\d{6,9}\b',
        },
        "ROUTING_NUMBER": {
            "standard_9_digits": r'\b\d{9}\b',
            "grouped_hyphen": r'\b\d{3}-\d{3}-\d{3}\b',
            "grouped_space": r'\b\d{3}\s\d{3}\s\d{3}\b',
            "grouped_dot": r'\b\d{3}\.\d{3}\.\d{3}\b',
            "with_prefix_routing_number": r'\bRouting\sNumber:\s?\d{9}\b',
            "with_prefix_routing_no": r'\bRouting\sNo:\s?\d{9}\b',
            "with_prefix_rtn": r'\bRTN:\s?\d{9}\b',
            "with_prefix_routing_hash": r'\bRouting\s#:\s?\d{9}\b',
            "with_prefix_aba_number": r'\bABA\sNumber:\s?\d{9}\b',
            "with_prefix_aba": r'\bABA:\s?\d{9}\b',
            "obfuscated_start": r'\b\*{4}\d{5}\b',
            "obfuscated_end": r'\b\d{5}\*{4}\b',
            "obfuscated_middle": r'\b\d{4}X{4}\d\b',
            "with_parentheses": r'\(\d{9}\)',
            "with_brackets": r'\[\d{9}\]',
            "with_curly_brackets": r'\{\d{9}\}',
            "with_trailing_special": r'\b\d{9}[#\.\!]\b',
            "with_country_code": r'\b[A-Z]{2}\d{9}\b',
            "alphanumeric_format": r'\b[A-Z]{2,4}\d{9}\b',
            "with_combined_info": r'\bRouting:\s?\d{9}\s?\|\s?Acct:\s?\d{7,13}\b',
        },
        "BANK_ACCOUNT": {
            "standard_9_digits": r'\b\d{9}\b',
            "standard_10_digits": r'\b\d{10}\b',
            "standard_11_digits": r'\b\d{11}\b',
            "standard_12_digits": r'\b\d{12}\b',
            "standard_13_digits": r'\b\d{13}\b',
            "grouped_hyphen": r'\b\d{3,4}-\d{3,4}-\d{3,4}\b',
            "grouped_space": r'\b\d{3,4}\s\d{3,4}\s\d{3,4}\b',
            "grouped_dot": r'\b\d{3,4}\.\d{3,4}\.\d{3,4}\b',
            "with_prefix_account_number": r'\bAccount\sNumber:\s?\d{7,13}\b',
            "with_prefix_acct_no": r'\bAcct\sNo:\s?\d{7,13}\b',
            "with_prefix_bank_acct": r'\bBank\sAcct#:\s?\d{7,13}\b',
            "with_prefix_acc_no": r'\bAcc#:\s?\d{3,4}-\d{3,4}-\d{3,4}\b',
            "obfuscated_start": r'\b\*{4}\d{5,9}\b',
            "obfuscated_end": r'\b\d{5,9}\*{4}\b',
            "obfuscated_middle": r'\b\d{3,4}\*{4}\d{3,4}\b',
            "obfuscated_all_x": r'\bX{4,6}\d{3,7}\b',
            "mixed_separators": r'\b\d{3,4}[-.\s]\d{3,4}[-.\s]\d{3,4}\b',
            "with_parentheses": r'\(\d{7,13}\)',
            "with_brackets": r'\[\d{7,13}\]',
            "with_curly_brackets": r'\{\d{7,13}\}',
            "with_trailing_special": r'\b\d{7,13}[\.\#]\b',
            "with_country_code": r'\b[A-Z]{2}\d{7,15}\b',
            "alphanumeric_format": r'\b[A-Z]{2,4}\d{7,13}\b',
            "iban_format": r'\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{0,16}\b',
            "with_routing_number": r'\bRouting\sNo:\s?\d{9},\s?Acct\sNo:\s?\d{7,13}\b',
            "routing_and_acct_separator": r'\bRouting:\s?\d{9}\s?\|\s?Acct:\s?\d{7,13}\b',
        },
        "PASSPORT": {
            "standard_single_letter": r'\b[A-Z]\d{7,8}\b',
            "standard_two_letters": r'\b[A-Z]{2}\d{7}\b',
            "numeric_only_9_digits": r'\b\d{9}\b',
            "numeric_only_8_digits": r'\b\d{8}\b',
            "numeric_only_7_digits": r'\b\d{7}\b',
            "grouped_digits_space": r'\b[A-Z]{1,2}\d{3}\s\d{3}\s\d{2,3}\b',
            "grouped_digits_hyphen": r'\b[A-Z]{1,2}\d{3}-\d{4,5}\b',
            "numeric_grouped_space": r'\b\d{3}\s\d{3}\s\d{3}\b',
            "numeric_grouped_hyphen": r'\b\d{3}-\d{3}-\d{3}\b',
            "country_code_prefix": r'\b[A-Z]{3}\s?[A-Z]{0,2}\d{7,9}\b',
            "obfuscated_last_4": r'\b[A-Z]{1,2}\d{3,4}\*{4}\b',
            "obfuscated_first_4": r'\b\*{4}\d{4}\b',
            "obfuscated_middle": r'\b[A-Z]{1,2}\*{4}\d{3}\b',
            "obfuscated_all_x": r'\b[A-Z]{1,2}X{7,8}\b',
            "with_prefix_ppn": r'\bPPN:\s?[A-Z]{1,2}\d{7,8}\b',
            "with_prefix_passport_no": r'\bPassport\sNo:\s?[A-Z]{1,2}\d{7,8}\b',
            "with_prefix_passport_hash": r'\bPassport\s#\s?\d{7,9}\b',
            "with_trailing_special": r'\b[A-Z]{1,2}\d{7,8}[#*]\b',
            "mixed_case": r'\b[a-zA-Z]{1,2}\d{7,9}\b',
            "with_parentheses": r'\(\b[A-Z]{1,2}\d{7,8}\b\)',
            "with_brackets": r'\[\b[A-Z]{1,2}\d{7,8}\b\]',
            "with_curly_brackets": r'\{\b\d{7,9}\b\}',
            "numeric_grouped_with_suffix": r'\b\d{7,9}/\d{2,4}\b',
            "year_prefix_letter_digit": r'\b\d{2}[A-Z]{1,2}\d{7,8}\b',
            "numeric_suffix": r'\b[A-Z]{1,2}\d{7,8}/\d{2,4}\b',
            "mixed_numeric_only": r'\b\d{4}\s\d{4}\s\d{2}\b',
        },
        "CREDIT_CARD": {
            "standard_hyphen": r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',
            "standard_space": r'\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b',
            "no_separator": r'\b\d{16}\b',
            "standard_dot": r'\b\d{4}\.\d{4}\.\d{4}\.\d{4}\b',
            "standard_underscore": r'\b\d{4}_\d{4}_\d{4}_\d{4}\b',
            "different_grouping_4_3_6_3": r'\b\d{4}\s\d{3}\s\d{6}\s\d{3}\b',
            "different_grouping_4_4_4_3": r'\b\d{4}-\d{4}-\d{4}-\d{3}\b',
            "different_grouping_4_4_5_3": r'\b\d{4}\.\d{4}\.\d{5}\.\d{3}\b',
            "different_grouping_4_5_3_4": r'\b\d{4}\s\d{5}\s\d{3}\s\d{4}\b',
            "leading_trailing_space": r'\s?\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b\s?',
            "partial_obfuscated_middle_x": r'\b\d{4}-X{4}-X{4}-\d{4}\b',
            "partial_obfuscated_middle_star": r'\b\d{4}-\*{4}-\*{4}-\d{4}\b',
            "partial_obfuscated_start": r'\b\*{4}-\*{4}-\*{4}-\d{4}\b',
            "partial_obfuscated_end": r'\b\d{4}-\d{4}-\d{4}-\*{4}\b',
            "full_obfuscated_x": r'\bX{4}-X{4}-X{4}-X{4}\b',
            "full_obfuscated_star": r'\b\*{4}-\*{4}-\*{4}-\*{4}\b',
            "mixed_separators_hyphen_space": r'\b\d{4}-\d{4}\s\d{4}-\d{4}\b',
            "mixed_separators_dot_hyphen_space": r'\b\d{4}\.\d{4}-\d{4}\s\d{4}\b',
            "with_prefix_cc": r'CC#:\s?\b\d{4}-\d{4}-\d{4}-\d{4}\b',
            "with_prefix_card_no": r'Card\sNo:\s?\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b',
            "with_trailing_special_char": r'\b\d{4}-\d{4}-\d{4}-\d{4}#\d{1,4}\b',
            "with_country_code": r'\+\d{1,3}\s\d{4}-\d{4}-\d{4}-\d{4}\b',
            "with_currency_code": r'\b\d{4}-\d{4}-\d{4}-\d{4}\s[A-Z]{3}\b',
            "with_parentheses": r'\(\d{4}-\d{4}-\d{4}-\d{4}\)',
            "with_brackets": r'\[\d{4}\s\d{4}\s\d{4}\s\d{4}\]',
            "with_comment_parentheses": r'\b\d{4}-\d{4}-\d{4}-\d{4}\s?\(.*\)\b',
            "with_comment_hash": r'\b\d{4}-\d{4}-\d{4}-\d{4}\s?#.*\b',
            "newline_separated": r'\b\d{4}\n\d{4}\n\d{4}\n\d{4}\b',
            "tab_separated": r'\b\d{4}\t\d{4}\t\d{4}\t\d{4}\b',
            "mixed_obfuscated_space_star": r'\b\d{4}\s\d{4}\s\*{4}\s\d{4}\b',
            "mixed_obfuscated_hyphen_x": r'\b\d{4}-X{4}-X{4}-X{4}\b',
        },
        "SSN": {
            "standard_hyphen": r'\b\d{3}-\d{2}-\d{4}\b',
            "standard_space": r'\b\d{3}\s\d{2}\s\d{4}\b',
            "standard_dot": r'\b\d{3}\.\d{2}\.\d{4}\b',
            "no_separator": r'\b\d{9}\b',
            "slash_separator": r'\b\d{3}/\d{2}/\d{4}\b',
            "underscore_separator": r'\b\d{3}_\d{2}_\d{4}\b',
            "with_prefix_ssn": r'\bSSN:\s?\d{3}-\d{2}-\d{4}\b',
            "with_prefix_ss_number": r'\bSocial Security Number:\s?\d{3}-\d{2}-\d{4}\b',
            "with_prefix_ss_hash": r'\bSS#:\s?\d{3}-\d{2}-\d{4}\b',
            "with_parentheses": r'\(\d{3}\)\s?\d{2}-\d{4}\b',
            "spaced_hyphen": r'\b\d{3}\s-\s\d{2}\s-\s\d{4}\b',
            "spaced_dot": r'\b\d{3}\s\.\s\d{2}\s\.\s\d{4}\b',
            "multiple_space": r'\b\d{3}\s{2,}\d{2}\s{2,}\d{4}\b',
            "trailing_hash": r'\b\d{3}-\d{2}-\d{4}#\b',
            "partial_obfuscated_start": r'\b(X{3}|[*]{3})-X{2}|[*]{2}-\d{4}\b',
            "partial_obfuscated_end": r'\b\d{3}-\d{2}-(X{4}|[*]{4})\b',
            "full_obfuscated_start": r'\b(X{3}|[*]{3})-X{2}|[*]{2}-(X{4}|[*]{4})\b',
            "full_obfuscated_end": r'\b\d{3}-XX-XXXX\b',
            "international_ssn": r'\bUSA\s\d{3}-\d{2}-\d{4}\b',
        },
        "EMAIL": {
            "standard": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "quoted_local": r'"[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+"@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "subdomains": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,3}\.[a-zA-Z]{2,}',
            "ipv4_domain": r'[a-zA-Z0-9._%+-]+@\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]',
            "ipv6_domain": r'[a-zA-Z0-9._%+-]+@\[(IPv6:[0-9a-fA-F:.]+)\]',
            "display_name": r'["]?[a-zA-Z0-9._%+\-\s]+["]? <[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>',
            "comments_local": r'[a-zA-Z0-9._%+-]+\(.*\)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "comments_domain": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\(.*\)',
            "idn_domain": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        },
        "PHONE_NUMBER": {
            "standard_us": r'\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b',
            "parentheses_us": r'\(\d{3}\)\s?\d{3}[-.\s]\d{4}\b',
            "numeric_only": r'\b\d{10}\b',
            "international_plus": r'\+\d{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',
            "international_zeroes": r'\b00\d{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',
            "international_no_spaces": r'\+\d{1,3}\(?\d{1,3}\)?\d{1,4}\d{1,4}\d{1,9}\b',
            "local_us": r'\b\d{3}[-.\s]\d{4}\b',
            "with_extension": r'\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\s?(x|ext\.?|extension)\s?\d{1,5}\b',
            "leading_one_us": r'\b1[-.\s]?\d{3}[-.\s]\d{3}[-.\s]\d{4}\b',
            "toll_free_us": r'\b1[-.\s]800[-.\s]\d{3}[-.\s]\d{4}\b',
            "international_uk": r'\+\d{2}[-.\s]?\d{4}[-.\s]?\d{6}\b',
            "uk_mobile": r'\+\d{2}[-.\s]?\d{4}[-.\s]?\d{6}\b',
            "australia_landline": r'\+\d{2}[-.\s]?\d{1}[-.\s]?\d{4}[-.\s]?\d{4}\b',
            "with_special_chars": r'\b\d{3}[-.\s]\d{3}[-.\s]\d{4}#\d{1,4}\b',
        }
    }

def precompile_patterns():
    raw_patterns = build_regex_patterns()
    compiled_patterns = {}
    for category, patterns in raw_patterns.items():
        compiled_patterns[category] = {label: re.compile(pattern) for label, pattern in patterns.items()}
    return compiled_patterns

def extract_patterns_from_text(text):
    compiled_patterns = precompile_patterns()
    extracted_data = {}

    for category, patterns in compiled_patterns.items():
        all_matches = []
        for label, regex in patterns.items():
            matches = regex.findall(text)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        all_matches.append(''.join(match))
                    else:
                        all_matches.append(match)
        
        all_matches = sorted(all_matches, key=len, reverse=True)
        
        filtered_matches = []
        for match in all_matches:
            if not any(match in longer_match for longer_match in filtered_matches):
                filtered_matches.append(match)

        if filtered_matches:
            extracted_data[category] = list(OrderedDict.fromkeys(filtered_matches))

    return extracted_data

# Example usage
text_to_scan = """
On January 15, 2024, at 13:45:30, John Doe sent an email to jane.doe@example.com with his location details: geo:40.7128,-74.0060. He also shared a website link https://www.example.com/info?query=123 for more information.

John drives a car with the license plate ABC1234 and lives in the postal code 10001. His vehicle's VIN is 1HGCM82633A123456, and his SWIFT code is BOFAUS3NXXX. He also mentioned his network configuration: an IPv6 CIDR block of 2001:0db8:85a3::/64 and an IPv4 CIDR block of 192.168.1.0/24.

For security, he listed his MAC address as 00:14:22:01:23:45 and his driver's license number as D1234567. His bank details include a routing number 021000021 and a bank account number 1234567890123456789. John also provided his passport number 123456789, credit card number 4111 1111 1111 1111, and SSN 123-45-6789.

If you need to reach him, his phone number is +1 (555) 123-4567.
"""

extracted_results = extract_patterns_from_text(text_to_scan)
print(json.dumps(extracted_results, indent=2))
