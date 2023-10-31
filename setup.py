#!/usr/bin/env python
"""Total Python"""
from setuptools import find_packages, setup

setup(name = 'totalPython',
    version = '0.1',
    description = "Simple program with Virus Total API integration",
    long_description = "Utilizing the VT API to do lookups on domains, URLs, checksums and IP addresses. ",
    platforms = ["Windows"],
    author="Ben Nicholay Gyllenhaal Johansen",
    author_email="ben.johansen@rema.no",
    url="https://github.com/B-Johansen/totalPython.git",
    license = "MIT",
    packages=find_packages()
    )