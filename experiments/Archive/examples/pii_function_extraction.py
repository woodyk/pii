#!/usr/bin/env python3
#
# pii_function_extraction.py

import re
import datetime
import json

class PIIExtractor:

    def _unique(self, items):
        # Helper method to return unique items in a list, maintaining the order
        seen = set()
        unique_items = []
        for item in items:
            identifier = item["match"]  # Use the 'match' value as the identifier for uniqueness
            if identifier not in seen:
                unique_items.append(item)
                seen.add(identifier)
        return unique_items

    def _add_score(self, default, confidence):
        total = default + confidence
        return total

    def _is_near_keywords(self, match, text, keywords, default_score, proximity=20):
        match_start = text.find(match)
        before_match = text[max(0, match_start - proximity):match_start].lower()
        after_match = text[match_start + len(match):min(len(text), match_start + len(match) + proximity)].lower()

        keyword_distances = []
        keyword_count = 0

        for keyword in keywords:
            before_index = before_match.rfind(keyword)
            after_index = after_match.find(keyword)

            if before_index != -1:
                distance = proximity - before_index
                keyword_distances.append(distance)
                keyword_count += 1
            if after_index != -1:
                distance = after_index
                keyword_distances.append(distance)
                keyword_count += 1

        if keyword_count == 0:
            return default_score  # No keywords found, return lowest confidence

        # Calculate the average distance of all found keywords
        average_distance = sum(keyword_distances) / len(keyword_distances)

        # Ensure average_distance does not exceed proximity to avoid negative proximity_score
        average_distance = min(average_distance, proximity)

        # Confidence score: the more keywords and the closer they are, the higher the score
        keyword_coverage = keyword_count / len(keywords)
        proximity_score = (proximity - average_distance) / proximity
        confidence = max(0.0, min(1.0, keyword_coverage * proximity_score))
        confidence = default_score + confidence

        return confidence

    def _is_valid_bank_account(self, account):
        # A placeholder for complex validation logic, such as checksums or country-specific rules.
        if re.match(r'^[A-Z]{2}\d{2}', account):  # Basic IBAN check
            return len(account) >= 15 and len(account) <= 34
        # Additional validation checks can be added here for other formats
        return True

    def extract_aadhaar(self, text):
        default_score = 0.5
        def verhoeff_checksum(aadhaar_number):
            verhoeff_table_d = [
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
                [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
                [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
                [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
                [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
                [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
                [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
                [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
                [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
            ]
            verhoeff_table_p = [
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
                [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
                [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
                [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
                [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
                [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
                [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
            ]
            verhoeff_table_inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
            c = 0
            for i, digit in enumerate(reversed(aadhaar_number)):
                c = verhoeff_table_d[c][verhoeff_table_p[i % 8][int(digit)]]
            return c == 0

        matches = re.findall(r'\b\d{12}\b', text)
        keywords = ["aadhaar", "uid", "uidai", "identification", "india"]

        results = []
        for match in matches:
            if verhoeff_checksum(match):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_australian_abn(self, text):
        default_score = 0.5
        def abn_checksum(abn):
            abn_weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
            abn_digits = [int(x) for x in abn]
            abn_digits[0] -= 1  # Subtract 1 from the first digit
            weighted_sum = sum(w * d for w, d in zip(abn_weights, abn_digits))
            return weighted_sum % 89 == 0

        matches = re.findall(r'\b\d{11}\b', text)
        keywords = ["abn", "australian", "business", "number", "tax", "identifier"]

        results = []
        for match in matches:
            if abn_checksum(match):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_bank_account(self, text):
        default_score = 0.3
        patterns = [
            r'\b\d{8,12}\b',  # Generic 8 to 12 digits (US, Canada)
            r'\b\d{9,18}\b',  # India (IFSC + Account)
            r'\b\d{2}-\d{2}-\d{2} \d{8}\b',  # UK (Sort Code + Account)
            r'\b\d{6} \d{8,9}\b',  # Australia (BSB + Account)
            r'\b\d{5} \d{7,12}\b',  # Canada (Transit Number + Account)
            r'\b\d{8} \d{7,10}\b',  # Germany (BLZ + Konto-Nummer)
            r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b',  # IBAN (General pattern)
        ]

        matches = []
        keywords = ["bank", "account", "iban", "bsb", "routing", "sort code", "branch code", "account number"]

        for pattern in patterns:
            potential_matches = re.findall(pattern, text)
            for match in potential_matches:
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                matches.append({"match": match, "confidence": confidence})

        valid_accounts = []
        for match in matches:
            if self._is_valid_bank_account(match["match"]):
                valid_accounts.append(match)

        return self._unique(valid_accounts)

    def extract_routing_number(self, text):
        default_score = 0.4
        pattern = r'\b\d{3}[- ]?\d{3}[- ]?\d{3}\b'
        matches = re.findall(pattern, text)
        routing_numbers = [re.sub(r'[- ]', '', match) for match in matches]
        keywords = ["routing", "aba", "bank", "code", "number", "banking", "transfer"]

        results = []
        for match in routing_numbers:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_birth_certificate(self, text):
        default_score = 0.3
        matches = re.findall(r'\bBC\d{9}\b', text)
        keywords = ["birth", "certificate", "registry", "document", "registration"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_brazilian_cpf(self, text):
        default_score = 0.5
        def cpf_checksum(cpf):
            cpf = [int(digit) for digit in cpf if digit.isdigit()]
            if len(cpf) != 11:
                return False
            for i in range(9, 11):
                value = sum((cpf[num] * ((i + 1) - num) for num in range(0, i)))
                check_digit = ((value * 10) % 11) % 10
                if check_digit != cpf[i]:
                    return False
            return True

        matches = re.findall(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b', text)
        keywords = ["cpf", "brazilian", "tax", "payer", "identification", "brazil"]

        results = []
        for match in matches:
            if cpf_checksum(match):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_company_registration(self, text):
        default_score = 0.4
        matches = re.findall(r'\bCRN\d{9}\b', text)
        keywords = ["company", "registration", "crn", "corporate", "identifier", "number"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_credit_card(self, text):
        default_score = 0.5
        def luhn_checksum(card_number):
            digits = [int(d) for d in card_number if d.isdigit()]
            checksum = 0
            reverse_digits = digits[::-1]
            for i, d in enumerate(reverse_digits):
                if i % 2 == 0:
                    checksum += d
                else:
                    checksum += sum(divmod(2 * d, 10))
            return checksum % 10 == 0

        matches = re.findall(r'\b(?:\d[ -]*?){13,19}\b', text)
        keywords = ["credit", "card", "number", "debit", "payment", "cc"]

        results = []
        for match in matches:
            if luhn_checksum(match):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_date(self, text):
        default_score = 0.2
        date_patterns = [
            r'\b\d{1,2}/\d{1,2}/\d{4}\b',
            r'\b\d{1,2}-\d{1,2}-\d{4}\b',
            r'\b\d{1,2}\.\d{1,2}\.\d{4}\b',
            r'\b\d{4}/\d{1,2}/\d{1,2}\b',
            r'\b\d{4}-\d{1,2}-\d{1,2}\b',
            r'\b\d{4}\.\d{1,2}\.\d{1,2}\b',
            r'\b(?:[Jj]anuary|[Ff]ebruary|[Mm]arch|[Aa]pril|[Mm]ay|[Jj]une|[Jj]uly|[Aa]ugust|[Ss]eptember|[Oo]ctober|[Nn]ovember|[Dd]ecember) \d{1,2}, \d{4}\b',
            r'\b\d{1,2} (?:[Jj]anuary|[Ff]ebruary|[Mm]arch|[Aa]pril|[Mm]ay|[Jj]une|[Jj]uly|[Aa]ugust|[Ss]eptember|[Oo]ctober|[Nn]ovember|[Dd]ecember) \d{4}\b',
            r'\b\d{1,2}(?:st|nd|rd|th)? (?:[Jj]anuary|[Ff]ebruary|[Mm]arch|[Aa]pril|[Mm]ay|[Jj]une|[Jj]uly|[Aa]ugust|[Ss]eptember|[Oo]ctober|[Nn]ovember|[Dd]ecember) \d{4}\b',
            r'\b(?:[Jj]an|[Ff]eb|[Mm]ar|[Aa]pr|[Mm]ay|[Jj]un|[Jj]ul|[Aa]ug|[Ss]ep|[Oo]ct|[Nn]ov|[Dd]ec) \d{1,2}, \d{4}\b',
            r'\b\d{1,2} (?:[Jj]an|[Ff]eb|[Mm]ar|[Aa]pr|[Mm]ay|[Jj]un|[Jj]ul|[Aa]ug|[Ss]ep|[Oo]ct|[Nn]ov|[Dd]ec) \d{4}\b',
            r'\b\d{1,2}/\d{1,2}/\d{2}\b',
            r'\b\d{1,2}-\d{1,2}-\d{2}\b',
            r'\b(?:[Jj]anuary|[Ff]ebruary|[Mm]arch|[Aa]pril|[Mm]ay|[Jj]une|[Jj]uly|[Aa]ugust|[Ss]eptember|[Oo]ctober|[Nn]ovember|[Dd]ecember) \d{1,2}(?:st|nd|rd|th)?, \d{4}\b',
            r'\b(?:[Jj]an|[Ff]eb|[Mm]ar|[Aa]pr|[Mm]ay|[Jj]un|[Jj]ul|[Aa]ug|[Ss]ep|[Oo]ct|[Nn]ov|[Dd]ec) \d{1,2}, \d{2}\b',
            r'\b\d{1,2} (?:[Jj]an|[Ff]eb|[Mm]ar|[Aa]pr|[Mm]ay|[Jj]un|[Jj]ul|[Aa]ug|[Ss]ep|[Oo]ct|[Nn]ov|[Dd]ec) \d{2}\b',
        ]

        matches = []
        keywords = ["date", "birthdate", "dob", "expiration", "issued", "valid until"]

        for pattern in date_patterns:
            potential_matches = re.findall(pattern, text)
            for match in potential_matches:
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                matches.append({"match": match, "confidence": confidence})

        valid_dates = []
        for match in matches:
            try:
                for fmt in ("%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d", "%Y-%m-%d", "%Y.%m.%d", "%d %B %Y", "%B %d, %Y", "%d %b %Y", "%b %d, %Y", "%d-%m-%Y", "%m-%d-%Y", "%b %d, %y", "%d %b %y"):
                    try:
                        datetime.datetime.strptime(match["match"], fmt)
                        valid_dates.append(match)
                        break
                    except ValueError:
                        continue
            except ValueError:
                continue

        return self._unique(valid_dates)

    def extract_drivers_license(self, text):
        default_score = 0.3
        matches = re.findall(r'\bD\d{9,12}\b', text)
        keywords = ["driver", "license", "dl", "permit", "identification", "number"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_drivers_license_international(self, text):
        default_score = 0.3
        matches = re.findall(r'\bINTD\d{9}\b', text)
        keywords = ["international", "driver", "license", "permit", "identification"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_email(self, text):
        default_score = 0.4
        matches = re.findall(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', text)
        keywords = ["email", "address", "contact", "mail", "e-mail"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        valid_emails = self._unique(results)
        return valid_emails

    def extract_financial_account_other(self, text):
        default_score = 0.4
        matches = re.findall(r'\bFA\d{9,12}\b', text)
        keywords = ["financial", "account", "investment", "retirement", "portfolio", "number"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_full_name(self, text):
        default_score = 0.2
        matches = re.findall(r'\b[A-Z][a-z]*\s[A-Z][a-z]*(\s[A-Z][a-z]*)?\b', text)
        keywords = ["name", "full", "first", "last", "middle", "surname", "title", "mr", "ms", "dr", "mrs", "miss"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_government_service_number(self, text):
        default_score = 0.4
        matches = re.findall(r'\bGS\d{9}\b', text)
        keywords = ["government", "service", "number", "gsn", "identifier", "public", "sector"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_health_id(self, text):
        default_score = 0.4
        matches = re.findall(r'\bHID\d{9}\b', text)
        keywords = ["health", "id", "identification", "medical", "hid", "number"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_health_insurance_other(self, text):
        default_score = 0.4
        matches = re.findall(r'\bHI\d{9}\b', text)
        keywords = ["health", "insurance", "policy", "number", "coverage", "plan", "hid"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_iban(self, text):
        default_score = 0.5
        def iban_checksum(iban):
            iban = iban.replace(' ', '')
            iban = iban[4:] + iban[:4]
            iban = ''.join(str(int(ch, 36)) for ch in iban)
            return int(iban) % 97 == 1

        matches = re.findall(r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b', text)
        keywords = ["iban", "international", "bank", "account", "number", "swift", "bic"]

        results = []
        for match in matches:
            if iban_checksum(match):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_ipv4_address(self, text):
        default_score = 0.5
        matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        valid_ipv4s = []
        keywords = ["ip", "ipv4", "internet", "address", "network", "connection"]

        for match in matches:
            octets = match.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                valid_ipv4s.append({"match": match, "confidence": confidence})

        return self._unique(valid_ipv4s)

    def extract_ipv6_address(self, text):
        default_score = 0.5
        matches = re.findall(r'\b([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b', text)
        keywords = ["ip", "ipv6", "internet", "address", "network", "connection"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_license_key(self, text):
        default_score = 0.3
        matches = re.findall(r'\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b', text)
        keywords = ["license", "key", "activation", "serial", "software", "product", "registration"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_mac_address(self, text):
        default_score = 0.4
        matches = re.findall(r'\b[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}[:-]{1}[0-9A-Fa-f]{2}\b', text)
        keywords = ["mac", "address", "network", "hardware", "device", "identifier"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_national_id_china(self, text):
        default_score = 0.5
        matches = re.findall(r'\b\d{18}\b', text)
        keywords = ["national", "id", "china", "identification", "number", "citizen"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_national_id_other(self, text):
        default_score = 0.4
        matches = re.findall(r'\bNID\d{9,12}\b', text)
        keywords = ["national", "id", "identification", "number", "citizen"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_passport(self, text):
        default_score = 0.4
        matches = re.findall(r'\b\d{9}\b', text)
        keywords = ["passport", "travel", "document", "number", "identification"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_passport_non_us(self, text):
        default_score = 0.4
        matches = re.findall(r'\b[A-Z]\d{8}\b', text)
        keywords = ["passport", "non-us", "foreign", "travel", "document", "number"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_phone_number(self, text):
        default_score = 0.3
        matches = re.findall(r'\b\+?\d{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', text)
        keywords = ["phone", "number", "contact", "mobile", "telephone"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_serial_number(self, text):
        default_score = 0.3
        matches = re.findall(r'\bSN\d{9}\b', text)
        keywords = ["serial", "number", "product", "identifier", "registration", "device"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_social_media_id(self, text):
        default_score = 0.2
        matches = re.findall(r'\b@[A-Za-z0-9_]{3,15}\b', text)
        keywords = ["social", "media", "id", "handle", "username", "profile", "account"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_ssn(self, text):
        default_score = 0.5
        matches = re.findall(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b', text)
        keywords = ["ssn", "social", "security", "number", "identifier", "taxpayer"]

        results = []
        for match in matches:
            if not match.startswith("000") and not match.endswith("0000"):
                confidence = self._is_near_keywords(match, text, keywords, default_score)
                results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_student_id(self, text):
        default_score = 0.4
        matches = re.findall(r'\bSTU\d{6}\b', text)
        keywords = ["student", "id", "identification", "university", "school", "number"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_swift(self, text):
        default_score = 0.5
        matches = re.findall(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b', text)
        keywords = ["swift", "bic", "code", "international", "bank", "identifier"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_tax_id_other(self, text):
        default_score = 0.4
        matches = re.findall(r'\bTAX\d{9,12}\b', text)
        keywords = ["tax", "identification", "number", "id", "tin", "vat"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_time(self, text):
        default_score = 0.2
        matches = re.findall(r'\b([01]?\d|2[0-3]):[0-5]\d(:[0-5]\d)?\b', text)
        keywords = ["time", "timestamp", "hour", "minute", "second", "o'clock"]

        results = []
        for match in matches:
            if isinstance(match, tuple):
                match = ":".join([part for part in match if part])  # Reconstruct the full time string
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_vehicle_id(self, text):
        default_score = 0.4
        matches = re.findall(r'\b[A-HJ-NPR-Z0-9]{17}\b', text)
        keywords = ["vehicle", "vin", "identification", "number", "car", "auto"]

        results = []
        for match in matches:
            confidence = self._is_near_keywords(match, text, keywords, default_score)
            results.append({"match": match, "confidence": confidence})

        return self._unique(results)

    def extract_all_words(self, text):
        # Regex pattern to match words and numbers
        pattern = r'\b\w+\b'
        matches = re.findall(pattern, text)
        return matches

    def extract_all(self, text):
        extracted_data = {}
        for method_name in dir(self):
            if method_name.startswith('extract_') and method_name != 'extract_all':
                method = getattr(self, method_name)
                results = method(text)
                if results:
                    extracted_data[method_name.replace('extract_', '').upper()] = results
        return extracted_data

# Example usage:
extractor = PIIExtractor()
text = """
A Comprehensive Guide to Digital Identity and Security
Introduction
In the digital age, managing and protecting personal and sensitive information is more critical than ever. Various forms of identification, financial details, and security measures are essential in our everyday lives. This document will explore different types of personal information and security measures, providing examples for each to illustrate their importance.

1. Identification Numbers
1.1 Aadhaar
The Aadhaar number is a 12-digit unique identifier issued by the Indian government to residents. For example, an Aadhaar number might look like 123412341234.

1.2 Australian ABN
The Australian Business Number (ABN) is an 11-digit identifier used by businesses in Australia. An example of an ABN is 12345678901.

1.3 Brazilian CPF
The Cadastro de Pessoas Físicas (CPF) is an 11-digit taxpayer identification number used in Brazil. An example is 123.456.789-09.

1.4 National ID (China)
In China, citizens have a national identification number that typically consists of 18 digits. For example, 123456789012345678.

1.5 National ID (Other)
Other countries have their own forms of national identification numbers. For instance, in the United Kingdom, a National Insurance number might look like QQ123456C.

1.6 Government Service Number
A Government Service Number (GSN) can vary by country but typically looks like GS123456789.

2. Financial Information
2.1 Bank Account
A bank account number is used to identify a specific bank account. For example, 12345678901234.

2.2 Credit Card
Credit cards have 16-digit numbers. For instance, 4111-1111-1111-1111.

2.3 IBAN
The International Bank Account Number (IBAN) is used for international transactions. An IBAN might look like GB33BUKB20201555555555.

2.4 SWIFT Code
The SWIFT code is a standard format for Business Identifier Codes (BIC). For example, DEUTDEFF.

2.5 Financial Account (Other)
Other financial accounts might include retirement accounts or investment portfolios, identified by account numbers such as FA123456789.

2.6 Tax ID (Other)
Tax Identification Numbers (TINs) vary by country. An example might be TAX12345678 for a generic tax ID.

3. Personal Information
3.1 Full Name
A full name is typically composed of a first name, middle name, and last name. For example, John Michael Doe.

3.2 Date of Birth
The date of birth is an essential identifier, such as 01/23/1985.

3.3 Birth Certificate
A birth certificate number might look like BC1234567890.

3.4 Email
An email address is a common form of communication and identification, such as john.doe@example.com.

3.5 Phone Number
Phone numbers can be formatted in various ways, such as +1-123-456-7890.

3.6 Social Media ID
A social media ID is the username or handle on a social platform, for example, @john_doe123.

4. Security Information
4.1 Password
Passwords are critical for securing accounts. An example might be P@ssw0rd123!.

4.2 Security Question
Security questions are used for account recovery, such as "What was your first pet's name?" with an answer like Fluffy.

4.3 Security Answer
The answer to a security question might be Fluffy.

4.4 License Key
Software often requires a license key, which might look like ABCD-EFGH-IJKL-MNOP.

4.5 Serial Number
Serial numbers are used for product identification, such as SN1234567890.

4.6 Student ID
A student ID might look like STU123456.

5. Travel Documents
5.1 Passport
A passport number is typically 9 digits, such as 123456789.

5.2 Passport Issue Date
The issue date of a passport might be 01/01/2020.

5.3 Passport Expiration Date
The expiration date of a passport might be 01/01/2030.

5.4 Passport (Non-US)
Non-US passports may have different formats, but a number might still look like A12345678.

6. Healthcare Information
6.1 Health ID
A health ID might be used in various countries, such as HID123456789.

6.2 Health Insurance (Other)
Other health insurance identifiers might look like HI123456789.

7. Technical Identifiers
7.1 MAC Address
A MAC address uniquely identifies network hardware, for example, 00:1A:2B:3C:4D:5E.

7.2 IPv4 Address
An IPv4 address is used in networking, such as 192.168.1.1.

7.3 IPv6 Address
An IPv6 address is the next generation of internet addressing, like 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

7.4 Vehicle ID
A Vehicle Identification Number (VIN) might look like 1HGCM82633A123456.

8. Miscellaneous Information
8.1 Company Registration
Company registration numbers vary but may look like CRN123456789.

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
"""

print(json.dumps(extractor.extract_all(text), indent=4))

