#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: flair_test.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 19:42:35
# Modified: 2025-03-24 13:37:45
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from flair.models import SequenceTagger
from flair.data import Sentence

def extract_names(text):
    sentence = Sentence(text)
    tagger.predict(sentence)
    return [
        entity.text
        for entity in sentence.get_spans('ner')
        if entity.get_label("ner").value == "PER"
    ]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: flair_test.py <filename>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()

        tagger = SequenceTagger.load("ner")  # You can change to "flair/ner-english-large" if needed
        names = extract_names(text)

        if names:
            print("Extracted Names:")
            for name in sorted(set(names)):
                print(f"- {name}")
        else:
            print("No names found.")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")

