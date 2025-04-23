#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: pii.py
# Author: Wadih Khairallah
# Description: 
# Created: 2024-12-01 12:12:08
# Modified: 2025-04-23 17:42:06


from patterns import PATTERNS
from textextract import (
        extract_text,
        clean_path,
        text_from_url,
        get_screenshot
    )

import json
import math
import re
import os
import subprocess
import magic
import hashlib
import pytesseract
import requests 
import pandas as pd
import speech_recognition as sr
import pdfplumber
import argparse
import shutil

from bs4 import BeautifulSoup
from collections import Counter, defaultdict
from docx import Document
from datetime import datetime
from mss import mss
from urllib.parse import urlparse
from io import StringIO
from PIL import Image
from pydub import AudioSegment

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
log = console.log

def clean_value(label, value):
    value = value.strip().replace("\n", "")

    if label == "windows_path":
        return value.rstrip(".").replace("\\\\", "\\")

    if label == "phone_number":
        # Remove coordinate matches: e.g. "37.7749, -122.4194"
        if re.search(r"\d+\.\d+,\s*-?\d+\.\d+", value):
            return None

        # Skip comma-suffixed duals (e.g. "123-45-6789, 9876")
        if ',' in value and not re.match(r"^\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}$", value):
            return None

        # Fix malformed parens like "282) 445-4983" → "(282) 445-4983"
        value = re.sub(r"^(\d{3})\)", r"(\1)", value)
        value = re.sub(r"\)(\d)", r") \1", value)

        return value

    return value

def process_screenshot(patterns, labels=None, output_json=False):
    """
    Capture screenshot across all monitors and run PII extraction on the OCR text.

    Args:
        patterns (list): List of regex patterns to search for in the text.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.

    Returns:
        dict: Dictionary containing extracted data grouped by pattern labels.
            Returns None if no text could be extracted from the screenshot.

    Note:
        The function automatically cleans up the temporary screenshot file after processing.
    """
    screenshot_path = get_screenshot()
    text = None

    try:
        text = text_from_image(screenshot_path)
    finally:
        # Always clean up the temporary screenshot
        try:
            if os.path.exists(screenshot_path):
                os.remove(screenshot_path)
        except Exception as e:
            log(f"Failed to remove temporary screenshot: {e}")

    if text:
        extracted_data = extract(text, patterns, labels)
        if extracted_data:
            if output_json:
                print(json.dumps({"screenshot": extracted_data}, indent=4, ensure_ascii=False))
            else:
                display_results(extracted_data, title="Results from Screenshot")
        return extracted_data
    else:
        return None

def process_url(url, patterns, labels=None, output_json=False):
    """
    Process a URL by extracting its text and running PII detection.

    Args:
        url (str): The URL to process.
        patterns (list): List of regex patterns to search for in the text.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.

    Returns:
        dict: Dictionary containing extracted data grouped by pattern labels.
            Returns None if no text could be extracted from the URL.
    """
    text = text_from_url(url)
    if text:
        extracted_data = extract(text, patterns, labels)
        if len(extracted_data) > 0:
            if output_json:
                print(json.dumps({url: extracted_data}, indent=4, ensure_ascii=False))
            else:
                display_results(extracted_data, title=f"Results for {url}")
        return extracted_data
    else:
        return None

def is_url(path):
    """
    Check if a given path is a valid URL.

    Args:
        path (str): The path to check.

    Returns:
        bool: True if the path matches a URL pattern (http/https/ftp), False otherwise.
    """
    return bool(re.match(r'^(?:http|ftp)s?://', path, re.IGNORECASE))

def validate_patterns(patterns):
    """
    Validate regex patterns to ensure they are correctly defined.

    Args:
        patterns (list): List of regex patterns to validate.

    Returns:
        list: List of valid regex patterns, excluding any invalid ones.

    Note:
        - Reports invalid patterns without stopping execution
        - Invalid patterns are skipped with an error message
        - Returns empty list if all patterns are invalid
    """
    valid_patterns = []
    for pattern in patterns:
        try:
            re.compile(pattern)
            valid_patterns.append(pattern)
        except re.error as e:
            print(f"Invalid pattern skipped: {pattern} -> {e}")
    return valid_patterns

def get_labels(patterns):
    """
    Retrieve available labels from the regex patterns.

    Args:
        patterns (list): List of regex patterns.

    Returns:
        list: Sorted list of unique labels found in the patterns.
            Labels are extracted from named groups (?P<label>).

    Note:
        Only includes labels from patterns using the (?P<label>) syntax.
    """
    labels = set()
    for pattern in patterns:
        match = re.search(r"\(\?P<(\w+)>", pattern)
        if match:
            labels.add(match.group(1))
    return sorted(labels)

def extract(text, patterns, labels=None):
    """
    Extract labeled data from input text using provided patterns.
    Uses simplified extraction logic from legacy extracti().

    Args:
        text (str): The text to analyze.
        patterns (list): List of regex patterns.
        labels (list, optional): Labels to filter by. Defaults to None.

    Returns:
        dict: Labeled dictionary of sorted match values.
    """
    if isinstance(labels, str):
        labels = [labels]

    filtered_patterns = patterns
    if labels:
        filtered_patterns = [
            p for p in patterns
            if any(re.search(rf"\(\?P<{label}>", p) for label in labels)
        ]

    results = defaultdict(set)

    for pattern in filtered_patterns:
        try:
            regex = re.compile(pattern)
            for match in regex.finditer(text):
                if match.groupdict():
                    for label, value in match.groupdict().items():
                        if value:
                            cleaned = clean_value(label, value.strip())
                            if label == "url":
                                cleaned = cleaned.rstrip("),.**")
                            results[label].add(cleaned)
        except re.error as e:
            print(f"Invalid regex skipped: {pattern}\nError: {e}", file=sys.stderr)

    return {
        label: sorted([m for m in matches if m is not None])
        for label, matches in results.items()
    }




def process_file(file_path, patterns, labels=None, output_json=False):
    """
    Extract and process text from a given file.

    Args:
        file_path (str): Path to the file to process.
        patterns (list): List of regex patterns.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.

    Returns:
        dict: Dictionary of extracted data from the file, or None if extraction fails.

    Note:
        - Supports multiple file types through the extract_text function
        - Can output results in both JSON and human-readable formats
        - Handles extraction failures gracefully
    """
    text = extract_text(file_path)
    if text:
        extracted_data = extract(text, patterns, labels)
        if len(extracted_data) > 0:
            if output_json:
                print(json.dumps({file_path: extracted_data}, indent=4, ensure_ascii=False))
            else:
                display_results(extracted_data, title=f"Results for {file_path}")
        return extracted_data
    else:
        return None

def process_directory(directory_path, patterns, labels=None, output_json=False, serial=False):
    """
    Recursively process all files in a directory and render results.

    Args:
        directory_path (str): Path to the directory to process.
        patterns (list): List of regex patterns.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.
        serial (bool, optional): If True, process each file separately. Defaults to False.

    Returns:
        dict: Aggregated or per-file extraction results.
    """
    results = {} if serial else {}

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_results = process_file(file_path, patterns, labels, output_json=False)

            if not file_results:
                continue

            if serial:
                results[file_path] = file_results
            else:
                for label, matches in file_results.items():
                    results.setdefault(label, set()).update(matches)

    # Convert sets to lists when aggregating
    if not serial:
        results = {label: list(vals) for label, vals in results.items()}

    if output_json:
        print(json.dumps(results, indent=4, ensure_ascii=False))
        return results

    # Rich‑formatted console output
    if serial:
        for file_path, file_results in results.items():
            display_results(file_results, title=f"Results for {file_path}")
    else:
        display_results(results, title="Aggregated Results")

    return results


def display_results(results, title="PII Extraction Results"):
    """
    Display extraction results in a formatted table.

    Args:
        results (dict): Dictionary of results grouped by label.
        title (str, optional): Title for the results table. Defaults to "PII Extraction Results".

    Note:
        - Uses rich library for formatted console output
        - Displays results in a table with rounded borders
        - Highlights matches in green
        - Handles multi-line results with proper wrapping
    """
    table = Table(title=title, box=box.ROUNDED, expand=True, show_lines=True)
    table.add_column("Label", style="bold cyan", no_wrap=True)
    table.add_column("Matches", style="white", overflow="fold")

    for idx, (label, matches) in enumerate(sorted(results.items())):
        if not matches:
            continue
        match_text = "\n".join(f"[green]{match}[/green]" for match in matches)
        table.add_row(f"[bold magenta]{label}[/bold magenta]", match_text)

    console.print(Panel(table, border_style="blue"))

def print_labels_in_columns(labels):
    """
    Print a list of labels in multiple columns to maximize screen space.

    Args:
        labels (list): List of labels to display.

    Note:
        - Automatically adjusts column width based on terminal size
        - Sorts labels alphabetically
        - Adds proper spacing between columns
        - Handles labels of varying lengths
    """
    labels.sort()
    term_width = shutil.get_terminal_size((80, 20)).columns
    max_label_len = max(len(label) for label in labels) + 2  # add spacing
    cols = max(1, term_width // max_label_len)
    rows = (len(labels) + cols - 1) // cols

    for row in range(rows):
        for col in range(cols):
            idx = col * rows + row
            if idx < len(labels):
                print(labels[idx].ljust(max_label_len), end='')
        print()

def main():
    parser = argparse.ArgumentParser(description="Extract PII or labeled patterns from files, directories, URLs, or screenshots.")
    parser.add_argument("path", help="Input file path, directory, URL, or screenshot keyword")
    parser.add_argument("--labels", help="Comma-separated list of labels to extract, or use --labels list to see available")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--serial", action="store_true", help="Output one file per result when running on a directory")
    parser.add_argument("--save", help="Save JSON output to file (used with --json)")
    args = parser.parse_args()

    if args.labels == "list":
        print("Available labels:\n")
        for label in get_labels(PATTERNS):
            print(f"  - {label}")
        return

    labels = [l.strip() for l in args.labels.split(",")] if args.labels else None

    raw_path = args.path

    if is_url(raw_path):
        process_url(raw_path, PATTERNS, labels, args.json)
        return

    if raw_path.lower() in {"screenshot", "screen", "capture"}:
        process_screenshot(PATTERNS, labels, args.json)
        return

    path = clean_path(raw_path)

    if not path:
        print(f"Error: Path '{raw_path}' is not a valid file, directory, or URL.")
        return

    if os.path.isdir(path):
        process_directory(path, PATTERNS, labels, args.json, serial=args.serial)
    elif os.path.isfile(path):
        process_file(path, PATTERNS, labels, args.json)
    else:
        print(f"Error: Path '{raw_path}' is not a recognized or supported input type.")


if __name__ == "__main__":
    main()

