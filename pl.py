import requests
from urllib.parse import urlparse
import re

# Function to check if the link uses HTTPS
def check_https(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme == "https"

# Function to check for common phishing patterns in the URL
def detect_phishing_patterns(url):
    suspicious_patterns = [r"login", r"verify", r"account", r"secure", r"paypal", r"bank"]
    return any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns)

# Function to check if the URL stores or requests credentials insecurely
def check_insecure_credential_handling(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            return "password" in content and "http://" in url
    except Exception:
        pass
    return False

# Function to check for suspicious behavior in the page content
def check_suspicious_content(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            keywords = ["free", "urgent", "win", "congratulations", "click here", "limited time"]
            return any(keyword in content for keyword in keywords)
    except Exception:
        pass
    return False

# Function to categorize the URL
def categorize_url(https_check, phishing_check, credential_check, suspicious_content):
    if not https_check or phishing_check or credential_check or suspicious_content:
        return "Potentially Unsafe"
    return "Safe"

def main():
    url = input("Enter the URL to analyze: ").strip()
    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # Default to http:// if scheme is missing
    
    # Perform security checks
    https_check = check_https(url)
    phishing_check = detect_phishing_patterns(url)
    credential_check = check_insecure_credential_handling(url)
    suspicious_content = check_suspicious_content(url)
    
    # Categorize and summarize the results
    category = categorize_url(https_check, phishing_check, credential_check, suspicious_content)
    
    print("\n--- Analysis Summary ---")
    print(f"HTTPS Check: {'Pass' if https_check else 'Fail'}")
    print(f"Phishing Patterns Detected: {'Yes' if phishing_check else 'No'}")
    print(f"Insecure Credential Handling: {'Yes' if credential_check else 'No'}")
    print(f"Suspicious Content Detected: {'Yes' if suspicious_content else 'No'}")
    print(f"\nCategorization: {category}")

if __name__ == "__main__":
    main()
