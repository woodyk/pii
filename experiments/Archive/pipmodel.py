#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: pipmodel.py
# Author: Wadih Khairallah
# Description: 
# Created: 2024-12-03 02:48:25
# Modified: 2024-12-03 02:48:50

import random
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from scipy.sparse import hstack

# Define the regex constructs and descriptions
selected_backslash_commands = {
    r"\\d": "Digits 0-9",
    r"\\D": "Non-digits",
    r"\\w": "Word characters (a-z, A-Z, 0-9, _)",
    r"\\W": "Non-word characters",
    r"\\s": "Whitespace characters",
    r"\\S": "Non-whitespace characters",
    r"\\n": "Newline character",
    r"\\t": "Tab character",
    r"\\\\": "Literal backslash"
}

# Function to generate synthetic data
def generate_contextual_dataset(commands, num_samples_per_class=200, seq_len=15):
    dataset = []
    for regex, description in commands.items():
        examples = []
        if regex == r"\\d":
            examples = [str(i) for i in range(10)]
        elif regex == r"\\D":
            examples = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-{}[]|;:'\\\",.<>?/`~")
        elif regex == r"\\w":
            examples = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
        elif regex == r"\\W":
            examples = list("!@#$%^&*()_+=-{}[]|;:'\\\",.<>?/`~")
        elif regex == r"\\s":
            examples = [" ", "\t", "\n"]
        elif regex == r"\\S":
            examples = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=-{}[]|;:'\\\",.<>?/`~")
        elif regex == r"\\n":
            examples = ["\n"]
        elif regex == r"\\t":
            examples = ["\t"]
        elif regex == r"\\\\":
            examples = ["\\"]

        examples = [
            ("".join(random.choices(examples, k=random.randint(1, seq_len))).ljust(seq_len), regex)
            for _ in range(num_samples_per_class)
        ]
        dataset.extend({"text": text, "label": label} for text, label in examples)
    return dataset

# Generate dataset
contextual_dataset = generate_contextual_dataset(selected_backslash_commands, num_samples_per_class=200)
texts = [entry["text"] for entry in contextual_dataset]
labels = [entry["label"] for entry in contextual_dataset]

# Prepare training and testing data
X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

# Define custom feature generator
class CustomFeatureGenerator(BaseEstimator, TransformerMixin):
    def fit(self, x, y=None):
        return self

    def transform(self, texts):
        features = np.array([
            [
                sum(c.isdigit() for c in text),
                sum(c.isalpha() for c in text),
                sum(c.isspace() for c in text),
                sum(not c.isalnum() and not c.isspace() for c in text)
            ]
            for text in texts
        ])
        return features

# Combine features
combined_features = FeatureUnion([
    ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(1, 5))),
    ('position', CountVectorizer(analyzer=lambda text: [f"{char}_pos_{i}" for i, char in enumerate(text)]))
])

# Generate features
X_train_combined = combined_features.fit_transform(X_train)
X_test_combined = combined_features.transform(X_test)

# Add custom features
custom_feature_gen = CustomFeatureGenerator()
X_train_custom = custom_feature_gen.fit_transform(X_train)
X_test_custom = custom_feature_gen.transform(X_test)
X_train_final = hstack([X_train_combined, X_train_custom])
X_test_final = hstack([X_test_combined, X_test_custom])

# Train Random Forest
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_classifier.fit(X_train_final, y_train)

# Evaluate model
y_pred_rf = rf_classifier.predict(X_test_final)
report = classification_report(y_test, y_pred_rf, target_names=list(selected_backslash_commands.keys()))

# Output evaluation report
print(report)

