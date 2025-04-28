# PII - Personal Identifiable Information Extractor

## Overview

**PII** is a command-line tool and Python library for extracting Personal Identifiable Information (PII) or any labeled patterns from files, directories, URLs, or live screenshots.

It leverages a flexible set of regex patterns and structured text extraction methods to find sensitive or labeled information across various input types.

- Supports file, directory, URL, and screenshot input
- Customizable extraction by label
- Rich CLI output or JSON format
- Designed for extensibility and clean installation

---

## Installation

You can install `pii` locally or globally using `pip` or `pipx`.

From the repository root:

```bash
pip install .
```

or

```bash
pipx install .
```

This will install the `pii` command globally.

---

## Usage

### Basic command

```bash
pii <path_or_url_or_keyword>
```

- `<path_or_url_or_keyword>` can be:
  - A file path
  - A directory
  - A URL (`http`, `https`, or `ftp`)
  - The word `screenshot` to capture and analyze your screen

### Options

| Option        | Description                                                               |
|---------------|---------------------------------------------------------------------------|
| `--labels`    | Comma-separated list of labels to extract (e.g., `email,phone_number`).   |
| `--labels`    | (without value) Show all available labels.                               |
| `--json`      | Output the results in JSON format.                                        |
| `--serial`    | When scanning a directory, output one result per file instead of merging. |
| `--save FILE` | Save JSON output to the specified file.                                   |

### Examples

Extract all available patterns from a file:

```bash
pii sample.txt
```

Extract only emails and phone numbers from a directory:

```bash
pii /path/to/folder --labels email,phone_number
```

Analyze a webpage URL:

```bash
pii https://example.com
```

Capture and analyze a screenshot:

```bash
pii screenshot
```

List all available extraction labels:

```bash
pii --labels
```

Save output as JSON:

```bash
pii document.pdf --json --save results.json
```

---

## Requirements

Dependencies are listed in `requirements.txt`.
