#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: spacy_test.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 19:26:19

import spacy
import sys
import os

def extract_names(text):
    doc = nlp(text)
    return [ent.text for ent in doc.ents if ent.label_ == "PERSON"]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: get_name.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]

    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    with open(filename, "r", encoding="utf-8") as file:
        text = file.read()

    nlp = spacy.load("en_core_web_sm")
    names = extract_names(text)

    if names:
        print("Extracted Names:")
        for name in names:
            print(f"- {name}")
    else:
        print("No names found.")
