#!/usr/bin/env python

import sys
import subprocess
from credentials import api_key  # Import the api_key from credentials.py
import requests
import base64


# Install requests from PyPi
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


# Check if requests is installed, if not, install it
try:
    import requests
except ImportError:
    install("requests")


class IPaddress:
    var_vtip = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }  # Use the imported api_key

    def __init__(self, var_ip):
        self.var_ip = var_ip

    def get_ip_report(self):
        var_urlIP = self.var_vtip + self.var_ip
        response = requests.get(var_urlIP, headers=self.headers)
        print(response.text)


class Domain:
    var_vtdomain = "https://www.virustotal.com/api/v3/domains/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }  # Use the imported api_key

    def __init__(self, var_domain):
        self.var_domain = var_domain

    def get_domain_report(self):
        var_urlDomain = self.var_vtdomain + self.var_domain
        response = requests.get(var_urlDomain, headers=self.headers)
        print(response.text)


class File:
    var_vtfile = "https://www.virustotal.com/api/v3/files/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }  # Use the imported api_key

    def __init__(self, var_file):
        self.var_file = var_file

    def get_file_report(self):
        var_urlFile = self.var_vtfile + self.var_file
        response = requests.get(var_urlFile, headers=self.headers)
        print(response.text)


class Url:
    var_vturl = "https://www.virustotal.com/api/v3/urls/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }  # Use the imported api_key

    def __init__(self, var_url=None):
        self.var_url = var_url

    def check_for_identifier(self):
        identifier_input = input("Do you have an identifier? (yes/no): ")
        if identifier_input.lower() == "no":
            self.var_url = self.generate_url_id(input("Enter URL: "))  # Generate URL ID here
            print(f"New URL identifier generated: {self.var_url}")
            return False
        elif identifier_input.lower() == "yes":
            self.var_url = input("Enter URL identifier: ")
            print("User has an identifier. Continue with the program.")
            return True
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")
            return False

    def generate_url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_url_report(self):
        var_urlUrl = self.var_vturl + self.var_url
        response = requests.get(var_urlUrl, headers=self.headers)
        print(response.text)


if __name__ == "__main__":
    choice = input(
        "Enter '1' for IP address, '2' for Domain, '3' for File, or '4' for URL: "
    )

    if choice == "1":
        ip_addr_instance = IPaddress(var_ip=input("Enter IP-address: "))
        ip_addr_instance.get_ip_report()

    elif choice == "2":
        domain_instance = Domain(var_domain=input("Enter Domain: "))
        domain_instance.get_domain_report()

    elif choice == "3":
        file_instance = File(var_file=input("Enter File Hash: "))
        file_instance.get_file_report()

    elif choice == "4":
        url_instance = Url()
        url_instance.check_for_identifier()
        url_instance.get_url_report()