#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: setup.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 14:40:57
# Modified: 2025-04-28 14:49:11

from setuptools import setup, find_packages

# Read requirements.txt
def read_requirements():
    with open("requirements.txt", "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="pii",
    version="0.1.0",
    author="Wadih Khairallah",
    description="Personal Identifiable Information (PII) extraction tool using regex patterns and text processing.",
    packages=[],
    py_modules=["pii", "textextract"],
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "pii=pii:main",
            "textextract=textextract:main",
        ],
    },
    include_package_data=True,
    python_requires=">=3.8",
)

