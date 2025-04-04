#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: pii.py
# Author: Wadih Khairallah
# Description: 
# Created: 2024-12-01 12:12:08
# Modified: 2025-04-04 01:26:15


from patterns import PATTERNS

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
from collections import Counter
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

def clean_path(path):
    if is_url(path):
        return path
    else:
        path = os.path.expanduser(path)
        path = os.path.abspath(path)
        
        if os.path.isfile(path) or os.path.isdir(path):
            return path

def get_screenshot():
    ''' Take screenshot and return text object for all text found in the image '''
    # Screenshot storage path
    path = r'/tmp/sym_screenshot.png'

    with mss() as sct:
        monitor = {"top": 0, "left": 0, "width": 0, "height": 0}
        
        for mon in sct.monitors:
            # get furthest left point
            monitor["left"] = min(mon["left"], monitor["left"])
            # get highest point
            monitor["top"] = min(mon["top"], monitor["top"])
            # get furthest right point
            monitor["width"] = max(mon["width"]+mon["left"]-monitor["left"], monitor["width"])
            # get lowest point
            monitor["height"] = max(mon["height"]+mon["top"]-monitor["top"], monitor["height"])
        
        screenshot = sct.grab(monitor)

    img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
    img_gray = img.convert("L")
    img_gray.save(path)

    return path

def extract_exif(file_path):
    exif_data = None
    try:
        result = subprocess.run(['exiftool', '-j', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            exif_data = json.loads(result.stdout.decode())[0]

    except Exception as e:
        log(f"Exiftool failed: {e}")

    return exif_data

def text_from_url(url):
    """
    Fetch and extract text from a given URL.

    Args:
        url (str): The website URL.

    Returns:
        str: Extracted plain text from the web page.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Remove non-visible elements
        for tag in soup(["script", "style", "noscript", "iframe", "header", "footer", "meta", "link"]):
            tag.decompose()

        text = soup.get_text(separator=" ")
        return text.strip()

    except requests.RequestException as e:
        print(f"Error fetching URL: {url} - {e}")
        return None

def process_screenshot(patterns, labels=None, output_json=False):
    """
    Capture screenshot across all monitors and run PII extraction on the OCR text.

    Args:
        patterns (list): List of regex patterns.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.
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
        print("Warning: No text extracted from screenshot.")
        return None

def process_url(url, patterns, labels=None, output_json=False):
    """
    Process a URL by extracting its text and running PII detection.

    Args:
        url (str): The URL to process.
        patterns (list): List of regex patterns.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.

    Returns:
        dict: Extracted data from the web page.
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
        print(f"Warning: No text extracted from {url}.")
        return None

def remove_special_chars(values):
    if isinstance(values, str):
        return re.sub(r"[^\-\.,\#A-Za-z0-9 ]+", "", values)
    elif isinstance(values, (list, tuple)):
        return [re.sub(r"[^\-\.,\#A-Za-z0-9 ]+", "", v) for v in values]
    return values

def extract_text(file_path):
    file_path = clean_path(file_path)
    mime_type = magic.from_file(file_path, mime=True)
    try:
        content = "" 
        if mime_type.startswith('text/') or mime_type in ['application/json', 'application/xml', 'application/x-yaml', 'text/markdown']:
            with open(file_path, 'r') as f:
                content = f.read()

        elif mime_type in ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
            content = text_from_excel(file_path)

        elif mime_type == 'application/pdf':
            content = text_from_pdf(file_path)

        elif mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            content = text_from_word(file_path)

        elif mime_type.startswith('image/'):
            content = text_from_image(file_path)

        elif mime_type.startswith('audio/'):
            content = text_from_audio(file_path)
        
        else:
            content = text_from_other(file_path)

        if len(content) > 0:
            content = content.encode('utf-8').decode('utf-8', errors='ignore')
            return content

        else:
            log(f"No content found for file: {file_path}")
            return None

    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def text_from_audio(audio_file):
    text = ""

    def audio_to_wav(file_path):
        # Extract the file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lstrip('.')

        # Use pydub to convert to WAV
        audio = AudioSegment.from_file(file_path, format=ext)
        wav_file_path = file_path.replace(ext, 'wav')
        audio.export(wav_file_path, format='wav')

        return wav_file_path

    recognizer = sr.Recognizer()
    _, ext = os.path.splitext(audio_file)
    # Convert the file to WAV if necessary
    if ext.lower() not in ['.wav', '.wave']:
        audio_file = audio_to_wav(audio_file)
    try:
        with sr.AudioFile(audio_file) as source:
            audio = recognizer.record(source)

        text = recognizer.recognize_google(audio)
    except sr.UnknownValueError:
        log("Google Speech Recognition could not understand audio")
        return None
    except sr.RequestError as e:
        log(f"Could not request results from Google Speech Recognition service; {e}")
        return None

    return text

def downloadImage(url):
    if is_image(url):
        filename = os.path.basename(urlparse(url).path)
        save_path = os.path.join('/tmp/', filename)

        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        return clean_path(save_path)
    else:
        log(f"Unable to pull image from {url}")
        return None

def is_image(file_path_or_url):
    try:
        if is_url(file_path_or_url):
            response = requests.head(file_path_or_url, allow_redirects=True)
            content_type = response.headers.get("Content-Type", "").lower()
            if content_type.startswith("image/"):
                return True
        else:
            mime = magic.from_file(file_path_or_url, mime=True)
            if mime.startswith("image/"):
                return True
    except Exception as e:
        return False

def is_url(path):
    return bool(re.match(r'^(?:http|ftp)s?://', path, re.IGNORECASE))

def text_from_pdf(pdf_path):
    """
    Extracts plain text from a PDF, including OCR for images.
    """
    plain_text = ""

    def extract_table_text(table):
        """Converts a PDF table to plain text."""
        table_text = ""
        for row in table:
            table_text += "\t".join(row) + "\n"
        return table_text

    def save_image(image_data, page_num, image_num):
        """Saves an image and extracts text from it using OCR."""
        image_text = ""
        image_path = f"/tmp/page-{page_num}-image-{image_num}.png"
        with open(image_path, "wb") as img_file:
            img_file.write(image_data)

        image_text = text_from_image(image_path)  # OCR processing
        return image_text

    with pdfplumber.open(pdf_path) as pdf:
        # Extract metadata
        metadata = pdf.metadata
        if metadata:
            for key, value in metadata.items():
                plain_text += f"{key}: {value}\n"
            plain_text += "\n"

        # Process each page
        if pdf.pages:
            for page_num, page in enumerate(pdf.pages, start=1):
                plain_text += f"\n\n--- Page {page_num} ---\n\n"

                # Extract text
                try:
                    text = page.extract_text()
                    if text:
                        plain_text += text + "\n"
                    else:
                        plain_text += "[No text found on this page]\n"
                except Exception as e:
                    log(f"Error extracting text from PDF: {pdf_path}\n{e}")

                # Extract tables
                try:
                    tables = page.extract_tables()
                    if tables:
                        for table_num, table in enumerate(tables, start=1):
                            plain_text += f"\n[Table {table_num}]\n"
                            plain_text += extract_table_text(table)
                    else:
                        plain_text += "\n[No tables found]\n"
                except Exception as e:
                    log(f"Error extracting tables from PDF: {pdf_path}\n{e}")

                # Extract images & OCR
                try:
                    if page.images:
                        for image_num, image in enumerate(page.images, start=1):
                            if "data" in image:
                                image_data = image["data"]
                                image_text = save_image(image_data, page_num, image_num)
                                plain_text += f"\n[Extracted Text from Image {image_num}]\n{image_text}\n"
                    else:
                        plain_text += "\n[No images found]\n"
                except Exception as e:
                    log(f"Error processing images in PDF: {pdf_path}\n{e}")

        return plain_text

def text_from_word(file_path):
    """
    Extracts plain text from a Word (.docx) file, including text, tables, and images with OCR.
    """
    file_path = clean_path(file_path)
    doc = Document(file_path)
    plain_text = ""

    # Extract text from paragraphs
    try:
        for paragraph in doc.paragraphs:
            if paragraph.text.strip():
                plain_text += paragraph.text.strip() + "\n\n"
    except Exception as e:
        log(f"Error extracting text from Word file: {file_path}\n{e}")
        return None

    # Extract text from tables
    try:
        for table_num, table in enumerate(doc.tables, start=1):
            plain_text += f"\n[Table {table_num}]\n"
            for row in table.rows:
                cells = [cell.text.strip() for cell in row.cells]
                plain_text += "\t".join(cells) + "\n"
    except Exception as e:
        log(f"Error extracting tables from Word file: {file_path}\n{e}")
        return None

    # Extract and process images
    try:
        image_num = 0
        for rel in doc.part.rels:
            if "image" in doc.part.rels[rel].target_ref:
                image_num += 1
                image_data = doc.part.rels[rel].target_part.blob  # Extract image data
                image_path = f"/tmp/word_image_{image_num}.png"
                
                # Save image
                with open(image_path, "wb") as img_file:
                    img_file.write(image_data)

                # Perform OCR on the extracted image
                image_text = text_from_image(image_path)
                plain_text += f"\n[Extracted Text from Image {image_num}]\n{image_text}\n"
    except Exception as e:
        log(f"Error extracting images from Word file: {file_path}\n{e}")
        return None

    return plain_text

def text_from_excel(file_path):
    file_path = clean_path(file_path)
    try:
        df = pd.read_excel(file_path)
        return df.to_csv(index=False)
    except Exception as e:
        log(f"Failed to convert Excel to CSV: {e}")
        return None

def text_from_image(file_path):
    """
    Extracts plain text from an image using OCR.
    """
    file_path = clean_path(file_path)
    try:
        with Image.open(file_path) as img:
            # Perform OCR to extract text
            extracted_text = pytesseract.image_to_string(img).strip()
            return extracted_text if extracted_text else None 
    except Exception as e:
        log(f"Failed to process image: {file_path}, Error: {e}")
        return None

def calculate_entropy(data):
    """Calculate Shannon entropy to assess randomness in the file."""
    if not data:
        return "0"
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return str(entropy)

def extract_strings(data):
    """Extract readable ASCII and Unicode strings."""
    ascii_regex = re.compile(rb'[ -~]{4,}')  # ASCII strings of length >= 4
    unicode_regex = re.compile(rb'(?:[\x20-\x7E][\x00]){4,}')  # Unicode UTF-16 strings
    strings = []
    strings.extend(match.decode('ascii') for match in ascii_regex.findall(data))
    strings.extend(match.decode('utf-16', errors='ignore') for match in unicode_regex.findall(data))
    return strings

def text_from_other(file_path):
    """
    Extracts information from a file of unknown or unsupported type and returns plain text output.
    """
    file_path = clean_path(file_path)
    file_stats = os.stat(file_path)
    creation_time = datetime.fromtimestamp(file_stats.st_ctime)
    modified_time = datetime.fromtimestamp(file_stats.st_mtime)
    
    file_info = {
        "File Path": str(file_path),
        "File Size (bytes)": str(file_stats.st_size),
        "Creation Time": str(creation_time),
        "Modification Time": str(modified_time),
        "Permissions": oct(file_stats.st_mode & 0o777),
        "MIME Type": str(magic.from_file(file_path, mime=True)),
        "Hashes": {},
        "Readable Strings": [],
        "Magic Numbers": None,
        "Embedded URLs": [],
        "Entropy": None,
        "Exif Data": {},
    }

    # Get EXIF data
    exif_data = extract_exif(file_path)
    if exif_data:
        for key, value in exif_data.items():
            file_info["Exif Data"][key] = value

    # Read the file as binary
    try:
        with open(file_path, 'rb') as file:
            binary_data = file.read()
            file_info["Hashes"]["SHA-256"] = hashlib.sha256(binary_data).hexdigest()
            file_info["Hashes"]["MD5"] = hashlib.md5(binary_data).hexdigest()
            file_info["Readable Strings"] = extract_strings(binary_data)[:10]  # Limit to 10 strings
            file_info["Entropy"] = calculate_entropy(binary_data)
            file_info["Magic Numbers"] = binary_data[:4].hex()
    except Exception as e:
        print(f"Error processing binary file {file_path}: {e}")
        return None

    # Generate plain text report
    report = [f"{key}: {value}" for key, value in file_info.items() if value]

    return "\n".join(report)

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

def process_file(file_path, patterns, labels=None, output_json=False):
    """
    Extract and process text from a given file.

    Args:
        file_path (str): Path to the file.
        patterns (list): List of regex patterns.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.

    Returns:
        dict: Extracted data from the file.
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
        print(f"Warning: No text extracted from {file_path}.")
        return None

def process_directory(directory_path, patterns, labels=None, output_json=False, serial=False):
    """
    Recursively process all files in a directory, aggregating results by default.

    Args:
        directory_path (str): Path to the directory.
        patterns (list): List of regex patterns.
        labels (list, optional): Specific labels to extract. Defaults to None.
        output_json (bool, optional): Whether to output results in JSON format. Defaults to False.
        serial (bool, optional): If set, process each file separately. Defaults to False.
    """
    results = {} if serial else {}

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_results = process_file(file_path, patterns, labels, output_json=False)

            if file_results:
                if serial:
                    results[file_path] = file_results
                else:
                    for label, matches in file_results.items():
                        if label not in results:
                            results[label] = set()
                        results[label].update(matches)

    if not serial:
        # Convert sets back to lists for JSON compatibility
        results = {label: list(matches) for label, matches in results.items()}

    if output_json:
        print(json.dumps(results, indent=4, ensure_ascii=False))
    else:
        if serial:
            for file_path, file_results in results.items():
                print(f"\nResults for {file_path}:")
                for label, matches in file_results.items():
                    print(f"\n[{label}]")
                    for match in matches:
                        print(f"  - {match}")
        else:
            print("\nAggregated Results:")
            for label, matches in results.items():
                print(f"\n[{label}]")
                for match in matches:
                    print(f"  - {match}")

def display_results(results, title="PII Extraction Results"):
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
    """
    Command-line interface for the extraction tool.
    Parses arguments and processes files, directories, or URLs.
    """
    parser = argparse.ArgumentParser(
        description="Extract patterns from files, directories, or URLs."
    )
    parser.add_argument(
        "path",
        type=str,
        nargs="?",
        help="File, directory, URL, or the keyword 'screenshot' to capture screen input.",
    )
    parser.add_argument(
        "--labels",
        nargs="*",
        help="Specific labels to extract (if empty, list available labels)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    parser.add_argument(
        "--serial",
        action="store_true",
        help="Process each file separately instead of aggregating results",
    )

    args = parser.parse_args()

    # If no arguments are provided, show help and label options
    if not any(vars(args).values()):
        parser.print_help()
        print("\nAvailable Labels:")
        available_labels = get_labels(PATTERNS)
        print_labels_in_columns(available_labels)
        return

    # If --labels used alone, list all available labels
    if args.labels is not None and len(args.labels) == 0:
        available_labels = get_labels(PATTERNS)
        print("\nAvailable Labels:")
        print_labels_in_columns(available_labels)
        return

    # Handle 'screenshot' mode
    if args.path and args.path.strip().lower() == "screenshot":
        print("Capturing screenshot...")
        process_screenshot(PATTERNS, args.labels, args.json)
        return

    # Handle all other path types
    if not args.path:
        print(
            "Error: No path provided. Use '--labels' alone to list available labels or specify a path to process."
        )
        return

    path = clean_path(args.path)

    if not path:
        print(f"Error: Path '{args.path}' is not a valid file, directory, or URL.")
        return

    if is_url(path):
        print(f"Processing URL: {path}")
        process_url(path, PATTERNS, args.labels, args.json)
    elif os.path.isdir(path):
        print(f"Processing directory: {path}")
        process_directory(path, PATTERNS, args.labels, args.json, serial=args.serial)
    elif os.path.isfile(path):
        print(f"Processing file: {path}")
        process_file(path, PATTERNS, args.labels, args.json)
    else:
        print(f"Error: Path '{args.path}' is not a recognized or supported input type.")


if __name__ == "__main__":
    main()

