#!/usr/bin/env python

import base64

class identifier:
    def __init__(self, url):
        self.url = url
        self.url_id = self.generate_url_id()

    def generate_url_id(self):
        return base64.urlsafe_b64encode(self.url.encode()).decode().strip("=")

    def print_details(self):
        print(f"URL: {self.url}, URL ID: {self.url_id}")
