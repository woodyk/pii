#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: transformers_test.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-03-23 19:28:37

from transformers import pipeline

ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

def extract_names(text):
    entities = ner(text)
    return [e['word'] for e in entities if e['entity_group'] == 'PER']

