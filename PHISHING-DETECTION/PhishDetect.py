import os
import re
import ipaddress
from urllib.parse import urlparse
from colorama import Fore, init
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

# List of common phishing keywords
phishing_keywords = ["login", "verify", "account", "update", "secure", "bank", "password", "signin", "confirm", "0"]

# Feature extraction functions
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    path = urlparse(url).path.split('/')
    return sum(1 for segment in path if segment)

def redirection(url):
    pos = url.find('//')
    return 1 if pos > 6 else 0

def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if "https" in domain else 0

def tinyURL(url):
    legitimate_shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'cli.gs']
    domain = urlparse(url).netloc
    if any(legitimate_domain in domain for legitimate_domain in legitimate_shorteners):
        return 0
    short_url_patterns = r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|cli\.gs|..."
    return 1 if re.search(short_url_patterns, url) else 0

def prefixSuffix(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

# Additional features for phishing detection
def contains_phishing_keywords(url):
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return 1
    return 0

def contains_suspicious_patterns(url):
    # Check for presence of IP address in URL
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    if ip_pattern.search(url):
        return 1

    # Check for multiple subdomains (e.g., http://secure-login.example.com)
    subdomain_pattern = re.compile(r'(\w+\.){3,}')
    if subdomain_pattern.search(url):
        return 1

    return 0

# User interaction functions
def analyze_url(url):
    # Classify URL based on features
    results = {
        "IP Address": havingIP(url),
        "@ Symbol": haveAtSign(url),
        "Length >= 54": getLength(url),
        "URL Depth": getDepth(url),
        "Redirection (//)": redirection(url),
        "HTTPS in Domain": httpDomain(url),
        "Shortened URL": tinyURL(url),
        "Prefix/Suffix (-)": prefixSuffix(url),
        "Phishing Keywords": contains_phishing_keywords(url),
        "Suspicious Patterns": contains_suspicious_patterns(url),
    }

    # Evaluate phishing status based on features
    phishing_status = "Phishing" if any(value == 1 for value in results.values()) else "Legitimate"
    results["Phishing Status"] = Fore.RED + phishing_status if phishing_status == "Phishing" else Fore.GREEN + phishing_status
    return results

def analyze_file(file_path):
    with open(file_path, "r") as file:
        urls = file.readlines()
    results = []
    for url in urls:
        url = url.strip()
        results.append({url: analyze_url(url)})
    return results

# Output color functions
def colorize_output(value):
    return Fore.GREEN + "Legitimate" if value == 0 else Fore.RED + "Phishing"

# Main function
def main():
    choice = input(Fore.YELLOW + "Enter 1 for single URL or 2 to analyze a file: ")
    if choice == "1":
        url = input(Fore.YELLOW + "Enter the URL: ").strip()
        results = analyze_url(url)
        print(Fore.CYAN + f"\nAnalysis for {url}:\n")

        # Prepare data for the table
        table_data = []
        for feature, value in results.items():
            table_data.append([Fore.MAGENTA + feature, value])

        # Print the table
        print(tabulate(table_data, headers=["Feature", "Result"], tablefmt="fancy_grid"))

    elif choice == "2":
        file_path = input(Fore.YELLOW + "Enter the file path (txt format): ").strip()
        if not os.path.isfile(file_path):
            print(Fore.RED + "File not found. Please try again.")
            return
        results = analyze_file(file_path)
        print(Fore.CYAN + "\nBatch Analysis Results:\n")

        # Process and print results for each URL
        for result in results:
            for url, analysis in result.items():
                print(Fore.GREEN + f"\nURL: {url}")
                table_data = []
                for feature, value in analysis.items():
                    table_data.append([Fore.MAGENTA + feature, value])

                # Print the table
                print(tabulate(table_data, headers=["Feature", "Result"], tablefmt="fancy_grid"))

    else:
        print(Fore.RED + "Invalid choice. Please restart the program.")

if __name__ == "__main__":
    main()
