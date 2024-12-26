import os
import re  # For pattern matching in email headers and URLs
import socket  # To resolve domain names to IP addresses
import requests  # Required for VirusTotal API integration
import time  # For delaying the GET request
from dotenv import load_dotenv  # Load environment variables from .env

# Load environment variables from the .env file
load_dotenv()

# Retrieve the VirusTotal API key
api_key = os.getenv("VT_API_KEY")


# Helper Functions
def check_spoofed_domain(domain):
    """
    Check if the domain is suspicious based on a trusted list.
    """
    trusted_domains = ["gmail.com", "yahoo.com", "hotmail.com"]
    if domain not in trusted_domains:
        return f"Suspicious domain detected: {domain}"
    return None


def check_blacklisted_ip(ip):
    """
    Check if an IP address is in a predefined blacklist.
    """
    blacklisted_ips = ["192.168.1.1", "123.456.789.000"]
    if ip in blacklisted_ips:
        return f"Blacklisted IP detected: {ip}"
    return None


# VirusTotal Integration
def analyze_url_with_virustotal(url, api_key):
    """
    Analyze a URL using the VirusTotal API v3.
    """
    submit_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        # Submit URL for analysis
        response = requests.post(submit_url, headers=headers, data={"url": url})
        if response.status_code != 200:
            return f"Error submitting URL for analysis: {response.status_code} - {response.text}"

        response_data = response.json()
        analysis_id = response_data["data"]["id"]

        # Wait for the analysis to complete
        time.sleep(15)

        # Retrieve the analysis report
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code != 200:
            return f"Error retrieving analysis results: {analysis_response.status_code} - {analysis_response.text}"

        analysis_data = analysis_response.json()
        stats = analysis_data["data"]["attributes"]["stats"]
        malicious_count = stats.get("malicious", 0)
        if malicious_count > 0:
            return f"Malicious URL detected: {url} ({malicious_count} engines flagged it as malicious)"

        return f"URL appears safe: {url} (Malicious count: {malicious_count})"
    except Exception as e:
        return f"An error occurred: {str(e)}"


# Analysis Functions
def analyze_email(email):
    """
    Analyze email address for suspicious patterns.
    """
    findings = []
    domain = email.split("@")[-1]

    # Check for spoofed domain
    domain_result = check_spoofed_domain(domain)
    if domain_result:
        findings.append(domain_result)

    # Check domain's IP against blacklist
    try:
        ip = socket.gethostbyname(domain)
        ip_result = check_blacklisted_ip(ip)
        if ip_result:
            findings.append(ip_result)
    except socket.gaierror:
        findings.append(f"Failed to resolve domain: {domain}")

    return findings


def analyze_email_header(header_text):
    """
    Analyze email headers for suspicious patterns.
    """
    findings = []

    # Extract IP addresses from "Received" fields
    received_pattern = re.compile(r"Received:.*?from .*?\[([\d\.]+)\]")
    ips = received_pattern.findall(header_text)

    for ip in ips:
        ip_result = check_blacklisted_ip(ip)
        if ip_result:
            findings.append(ip_result)

    # Extract the sender's domain (from "From:" field)
    from_pattern = re.compile(r"From:.*?@([a-zA-Z0-9.-]+)")
    match = from_pattern.search(header_text)
    if match:
        domain = match.group(1)
        domain_result = check_spoofed_domain(domain)
        if domain_result:
            findings.append(domain_result)

    return findings


def analyze_directory(directory):
    """
    Analyze all email header files in a directory.
    """
    findings = []
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            file_path = os.path.join(directory, filename)
            with open(file_path, "r") as file:
                print(f"\nAnalyzing {filename}...")
                header_text = file.read()
                file_findings = analyze_email_header(header_text)
                if file_findings:
                    findings.append((filename, file_findings))
                else:
                    print(f"No suspicious patterns detected in {filename}.")
    return findings


# Main Script
if __name__ == "__main__":
    print("Phishing Email Detector")
    print("Choose an input type:")
    print("1. Analyze email headers")
    print("2. Analyze email address or link")
    print("3. Analyze email header files in a directory")

    choice = input("Enter your choice (1, 2, or 3): ").strip()

    if choice == "1":
        header_lines = []
        print("\nPaste the email headers below (end input with a blank line):")
        while True:
            line = input()
            if not line.strip():
                break
            header_lines.append(line)
        header_text = "\n".join(header_lines)
        findings = analyze_email_header(header_text)
        if findings:
            print("\nSuspicious patterns detected:")
            for finding in findings:
                print(f" - {finding}")
        else:
            print("\nNo suspicious patterns detected.")

    elif choice == "2":
        email = input("Enter an email address to analyze: ").strip()
        findings = analyze_email(email)
        if findings:
            print("\nSuspicious patterns detected in email address:")
            for finding in findings:
                print(f" - {finding}")
        else:
            print("\nEmail address appears safe.")

        link = input("\nEnter a link to analyze: ").strip()
        if link and api_key:
            print("\nAnalyzing link with VirusTotal...")
            print(analyze_url_with_virustotal(link, api_key))
        else:
            print("No link provided or API key missing.")

    elif choice == "3":
        directory = input(
            "Enter the directory path containing email header files: "
        ).strip()
        if os.path.isdir(directory):
            directory_findings = analyze_directory(directory)
            for filename, file_findings in directory_findings:
                print(f"\nFindings in {filename}:")
                for finding in file_findings:
                    print(f" - {finding}")
        else:
            print("Invalid directory path!")
    else:
        print("Invalid choice!")
