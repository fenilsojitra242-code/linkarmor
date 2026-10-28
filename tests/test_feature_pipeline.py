"""
Unit tests for URL feature extraction heuristics and preprocessing.
"""

import pytest

def test_url_length_calculation():
    sample_url = "https://secure-login.bank-update.verify-account.com/auth/login?session=893274"
    assert len(sample_url) > 50

def test_ip_address_detection():
    ip_url = "http://192.168.1.105/malware.exe"
    hostname = ip_url.split("//")[1].split("/")[0]
    is_ip = all(part.isdigit() for part in hostname.split("."))
    assert is_ip is True

def test_protocol_parsing():
    https_url = "https://github.com"
    http_url = "http://example.com"
    assert https_url.startswith("https://")
    assert http_url.startswith("http://")

def test_keyword_matching():
    suspicious_url = "http://paypal-verification-account-update.xyz/login.php"
    keywords = ["login", "verify", "account", "banking", "update"]
    found_keywords = [kw for kw in keywords if kw in suspicious_url]
    assert len(found_keywords) >= 3
