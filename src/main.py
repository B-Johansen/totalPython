#!/usr/bin/env python

import tkinter as tk
from tkinter import messagebox, simpledialog
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
        return response.text  # return the response text as a string


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
        return response.text


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
        return response.text

class Url:
    var_vturl = "https://www.virustotal.com/api/v3/urls/"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }  # Use the imported api_key

    def __init__(self, var_url=None):
        self.var_url = var_url

    def check_for_identifier(self):
        identifier_input = messagebox.askquestion("Identifier", "Do you have an identifier?")
        if identifier_input == "no":
            url = simpledialog.askstring("Input", "Enter URL:")
            self.var_url = self.generate_url_id(url)  # Generate URL ID here
            messagebox.showinfo("Information", f"New URL identifier generated: {self.var_url}")
            return False
        elif identifier_input == "yes":
            self.var_url = simpledialog.askstring("Input", "Enter URL identifier:")
            messagebox.showinfo("Information", "User has an identifier. Continue with the program.")
            return True

    def generate_url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_url_report(self):
        var_urlUrl = self.var_vturl + self.var_url
        response = requests.get(var_urlUrl, headers=self.headers)
        return response.text

def run_program():
    output.delete(1.0, tk.END)  # Clear the output field before running the program
    choice = variable.get()

    if choice == "IP address":
        ip_addr = simpledialog.askstring("Input", "Enter IP-address:")
        ip_addr_instance = IPaddress(var_ip=ip_addr)
        result = ip_addr_instance.get_ip_report()
        output.insert(tk.END, result)

    elif choice == "Domain":
        domain = simpledialog.askstring("Input", "Enter Domain:")
        domain_instance = Domain(var_domain=domain)
        result = domain_instance.get_domain_report()
        output.insert(tk.END, result)

    elif choice == "File":
        file_hash = simpledialog.askstring("Input", "Enter File Hash:")
        file_instance = File(var_file=file_hash)
        result = file_instance.get_file_report()
        output.insert(tk.END, result)

    elif choice == "URL":
        url_instance = Url()
        url_instance.check_for_identifier()
        result = url_instance.get_url_report()
        output.insert(tk.END, result)


root = tk.Tk()
root.geometry("500x400")

label = tk.Label(root, text="Select an option and run the program")
label.pack()

options = ['IP address', 'Domain', 'File', 'URL']
variable = tk.StringVar(root)
variable.set(options[0])

dropdown = tk.OptionMenu(root, variable, *options)
dropdown.pack()

run_button = tk.Button(root, text="Run Program", command=run_program)
run_button.pack()

output = tk.Text(root, height=10, width=50)
output.pack()

root.mainloop()