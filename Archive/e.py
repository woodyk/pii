#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: e.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-10 15:48:48
# Modified: 2025-03-10 17:04:36

import re
import argparse
import json
from patterns import PATTERNS


def validate_patterns(patterns):
    """
    Validate regex patterns to ensure they are correctly defined.
    Reports invalid patterns without stopping execution.
    Args:
        patterns (list): List of regex patterns.
    Returns:
        list: List of valid regex patterns.
    """
    valid_patterns = []
    for pattern in patterns:
        try:
            re.compile(pattern)
            valid_patterns.append(pattern)
        except re.error as e:
            print(f"Invalid pattern skipped: {pattern} -> {e}")
    return valid_patterns


def extract_patterns(text, patterns):
    """
    Extract matches from a flat list of regex patterns.
    Args:
        text (str): Input text to analyze.
        patterns (list): List of validated regex patterns.
    Returns:
        dict: Extracted matches grouped by inferred labels.
    """
    matches_by_label = {}
    for pattern in patterns:
        match = re.search(r"\(\?P<(\w+)>", pattern)  # Extract label from (?P<label>)
        if match:
            label = match.group(1)
            if label not in matches_by_label:
                matches_by_label[label] = []
            compiled_regex = re.compile(pattern)
            for match in compiled_regex.finditer(text):
                value = match.group()
                if value and value not in matches_by_label[label]:
                    matches_by_label[label].append({
                        "value": value,
                        "start": match.start(),
                        "end": match.end()
                    })
    return matches_by_label


def stitch_results(text, matches_by_label):
    """
    Stitch contiguous matches into cohesive results for each label.
    Args:
        text (str): Input text to analyze.
        matches_by_label (dict): Extracted matches grouped by label.
    Returns:
        dict: Stitched matches grouped by label.
    """
    stitched_results = {}
    for label, matches in matches_by_label.items():
        if not matches:
            continue

        # Sort matches by start position
        matches = sorted(matches, key=lambda m: m["start"])
        stitched = []
        current = matches[0]

        for match in matches[1:]:
            if current["end"] >= match["start"]:
                # Extend current match if contiguous
                current["value"] += text[current["end"]:match["start"]] + match["value"]
                current["end"] = match["end"]
            else:
                stitched.append(current)
                current = match

        # Add the final match
        if current:
            stitched.append(current)

        # Deduplicate and store stitched values
        stitched_results[label] = list({m["value"].strip() for m in stitched})

    return stitched_results


def sanitize_results(results):
    """
    Sanitize extracted matches to correct formatting issues and deduplicate results.
    Args:
        results (dict): Extracted matches grouped by label.
    Returns:
        dict: Sanitized matches grouped by label.
    """
    sanitized_results = {}
    for label, matches in results.items():
        sanitized_matches = []
        for match in matches:
            # Standardize Windows path formatting
            if label == "windows_path":
                sanitized_value = match.replace("\\\\", "\\")  # Normalize to single backslash
            else:
                sanitized_value = match
            # Remove trailing periods
            sanitized_value = sanitized_value.rstrip(".")
            sanitized_matches.append(sanitized_value)
        # Deduplicate matches
        sanitized_results[label] = list(set(sanitized_matches))
    return sanitized_results


def get_labels(patterns):
    """
    Retrieve available labels from the regex patterns.
    Args:
        patterns (list): List of regex patterns.
    Returns:
        list: List of unique labels found in the patterns.
    """
    labels = set()
    for pattern in patterns:
        match = re.search(r"\(\?P<(\w+)>", pattern)
        if match:
            labels.add(match.group(1))
    return sorted(labels)


def extract(input_data, patterns, labels=None):
    """
    Central access point for extraction.
    Args:
        input_data (str): Input text data to analyze.
        patterns (list): List of regex patterns.
        labels (list or str, optional): Labels to filter extraction. Defaults to None.
    Returns:
        dict: Extracted matches grouped by label.
    """
    # Normalize labels to a list if a single string is provided
    if isinstance(labels, str):
        labels = [labels]

    # Sanitize input text
    text = re.sub(r'\s+', ' ', ''.join(filter(str.isprintable, input_data)))

    # Filter patterns based on labels
    if labels:
        filtered_patterns = [p for p in patterns if any(re.search(rf"\(\?P<{label}>", p) for label in labels)]
    else:
        filtered_patterns = patterns

    # Validate patterns
    valid_patterns = validate_patterns(filtered_patterns)

    # Extract patterns
    matches_by_label = extract_patterns(text, valid_patterns)

    # Stitch results
    stitched_results = stitch_results(text, matches_by_label)

    # Sanitize results
    sanitized_results = sanitize_results(stitched_results)

    return sanitized_results


def main():
    """
    Command-line interface for the extraction tool.
    Parses arguments and processes files or text input.
    """
    parser = argparse.ArgumentParser(description="Extract patterns from a file or input text.")
    parser.add_argument("file", type=str, help="File to process")
    parser.add_argument("--labels", type=str, nargs="+", help="Specific labels to extract (optional)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            input_data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Perform extraction
    extracted_data = extract(input_data, PATTERNS, args.labels)

    # Print output
    if args.json:
        print(json.dumps(extracted_data, indent=4, ensure_ascii=False))
    else:
        for label, matches in extracted_data.items():
            print(f"\n[{label}]")
            for match in matches:
                print(f"  - {match}")


if __name__ == "__main__":
    main()

