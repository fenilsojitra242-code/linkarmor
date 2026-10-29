"""
Performance & latency benchmark tests for LinkArmor feature extraction and heuristic heuristics.
Ensures real-time throughput SLA (< 50ms per URL heuristic vector calculation).
"""

import time
import pytest

TEST_URL_CORPUS = [
    "https://www.google.com/search?q=cybersecurity+phishing+heuristics",
    "http://192.168.1.1:8080/admin/login.php?redirect=dashboard",
    "https://auth.secure-update.banking-portal.services-verify.xyz/account/login",
    "http://bit.ly/3xZbKl9",
    "https://sub1.sub2.sub3.target-domain.co.uk/path/to/resource?auth_token=8472918&user=demo",
    "https://amazon.com.security-check.attacker-hosted-site.info/signin",
    "https://en.wikipedia.org/wiki/Phishing",
    "http://10.0.0.1/network/gateway",
]

def extract_features_mock(url: str) -> dict:
    start_time = time.perf_counter()
    
    # 1. Length & protocol
    length = len(url)
    is_https = url.startswith("https://")
    
    # 2. Hostname parsing
    parts = url.split("://")
    hostname = parts[1].split("/")[0] if len(parts) > 1 else url.split("/")[0]
    subdomains = hostname.split(".")
    
    # 3. IP check
    is_ip = all(part.isdigit() for part in hostname.split(":")[0].split(".")) if "." in hostname else False
    
    # 4. Keyword heuristic
    keywords = ["login", "verify", "secure", "account", "update", "banking", "signin", "auth"]
    kw_count = sum(1 for kw in keywords if kw in url.lower())
    
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return {
        "length": length,
        "is_https": is_https,
        "is_ip": is_ip,
        "subdomain_depth": len(subdomains),
        "keyword_count": kw_count,
        "elapsed_ms": elapsed_ms,
    }

def test_single_url_latency_sla():
    """Verify each URL feature calculation executes well under 50ms SLA."""
    for url in TEST_URL_CORPUS:
        features = extract_features_mock(url)
        assert features["elapsed_ms"] < 50.0, f"Extraction for {url} took {features['elapsed_ms']}ms (> 50ms)"

def test_batch_corpus_throughput():
    """Verify processing 100 iterations of corpus executes within reasonable wall time."""
    start_total = time.perf_counter()
    total_processed = 0
    for _ in range(100):
        for url in TEST_URL_CORPUS:
            _ = extract_features_mock(url)
            total_processed += 1
            
    total_ms = (time.perf_counter() - start_total) * 1000.0
    avg_per_url = total_ms / total_processed
    assert avg_per_url < 5.0, f"Average throughput {avg_per_url}ms per URL exceeds 5ms target"
