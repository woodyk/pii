# PII Library & CLI Tool

A Python package and command line tools for extracting Personally
Identifiable Information (PII) and text/metadata from files, URLs,
directories, and screenshots.

## Features

- Extract PII patterns (emails, phone numbers, IPs, etc.) from text.
- Extract text and metadata from various file types (PDF, Word,
  Excel, images, audio).
- Support for URL fetching and web page text extraction.
- Recursive directory scans with aggregated or per-file results.
- Screenshot capture and OCR integration.
- Dual use as a Python library or CLI tools (`pii`, `textextract`).

## Installation

Install from PyPI:

```bash
pip install pii
```

Install from GitHub (latest):

```bash
pip install git+https://github.com/yourusername/pii.git
```

Development install (editable):

```bash
pip install -e .
```

## Command Line Usage

### `pii`

```bash
# Extract PII from a text file
pii path/to/file.txt

# Extract PII from a URL, output as JSON
pii https://example.com --json

# Scan a directory, show per-file results
pii /path/to/dir --serial

# Capture screenshot and extract PII
pii screenshot

# Filter by specific labels (e.g., email, phone_number)
pii path/to/file.txt --labels email phone_number
```

To list all supported PII labels:

```bash
pii --labels
```

### `textextract`

```bash
# Extract text from a PDF or other file
textextract document.pdf

# Extract metadata instead of text
textextract document.docx --metadata
```

## Python API

Import and use functions directly in your code:

```python
import pii
from pii import extract, extract_text

# Extract raw text from a PDF
text = extract_text("report.pdf")

# Extract only emails and phone numbers
data = extract(text, labels=["email", "phone_number"])

# Work with file paths or URLs
data_file = pii.file("data.csv")
data_url = pii.url("https://example.com/data")
```

Key functions in `pii` module:

- `extract(text, labels=None)`: Return dict of PII matches.
- `file(path, labels=None)`: Extract from a single file.
- `url(path, labels=None)`: Extract from a URL.
- `screenshot(labels=None)`: Capture and extract from screenshot.
- `directory(path, labels=None, serial=False)`: Scan directory.
- `get_labels()`: List all available PII labels.
- `display(results, title)`: Pretty-print results.

Key functions in `textextract` module:

- `extract_text(path)`: Extract text from various file types.
- `text_from_url(url)`: Fetch and parse web page text.
- `extract_metadata(path)`: Retrieve detailed file metadata.
- `clean_path(path)`: Normalize and validate file paths.
- `get_screenshot()`: Capture screenshot to a temp file.

## Contributing

Contributions are welcome! Please fork the repository, create a
feature branch, and open a pull request with clear descriptions and
tests.

## License

This project is licensed under the MIT License. See `LICENSE` file
for details.

