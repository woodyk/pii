# pii.py

`pii.py` is a Python script designed for the extraction of Personally Identifiable Information (PII) from various data sources. By leveraging Optical Character Recognition (OCR) and regex pattern matching, it enables users to capture sensitive information from images, documents, URLs, and even audio files. This repository is a collection of OSINT and PII extraction experiments.

## Features

- **Screenshot Capture**: Take screenshots and extract text using OCR.
- **File Processing**: Supports multiple file formats including PDF, Word, Excel, and various image/audio formats.
- **Web Text Extraction**: Fetch and extract text from webpages.
- **Label-Based Extraction**: Utilize custom regex patterns to filter and identify specific types of data.
- **JSON Output**: Option to output results in JSON format.
- **Multi-file and Directory Support**: Process files individually or aggregate results from an entire directory.
- **Error Handling**: Alerts for issues during processing.

## Installation

To run `pii.py`, ensure you have Python 3.x installed along with the required dependencies:

```bash
pip install -r requirements.txt
```

You might need to install additional system dependencies for features such as OCR and file type detection.

## Usage

### Command-Line Interface

To interact with the script, you can run it from the command line. Below are the examples of how to use it.

#### Capture Screenshot

```bash
python pii.py screenshot --labels <label1> <label2> --json
```

#### Process a File

```bash
python pii.py path/to/your/file --labels <label1> <label2> --json
```

#### Process a Directory

```bash
python pii.py path/to/your/directory --labels <label1> <label2>
```

#### Process a URL

```bash
python pii.py <url> --labels <label1> <label2>
```

#### List Available Labels

To see the available labels without processing anything:

```bash
python pii.py --labels
```

### Arguments

- `path`: The file path, directory path, or URL to process.
- `--labels`: List of specific labels to extract. If empty, it will list all available labels.
- `--json`: Outputs results in JSON format.
- `--serial`: Processes each file separately instead of aggregating results.

### Example

To extract emails and phone numbers from a PDF file and output results in JSON format:

```bash
python pii.py path/to/document.pdf --labels email phone --json
```

## Dependencies

- `pytesseract`: for OCR operations
- `requests`: for making HTTP requests to fetch webpage content
- `beautifulsoup4`: for parsing HTML and extracting text
- `pandas`: for processing Excel files
- `pdfplumber`: for extracting text from PDF files
- `python-docx`: for working with Word documents
- `mss`: for capturing screenshots
- `python-speech-recognition`: for transcribing audio files

Additional dependencies can be found in the `requirements.txt` file.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss potential changes.
