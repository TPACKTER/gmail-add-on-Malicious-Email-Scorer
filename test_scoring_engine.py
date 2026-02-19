import pytest
import asyncio
from scoring_engine import (
    calculate_risk_score, 
    analyze_urls_advanced, 
    analyze_brand_impersonation,
    detect_html_smuggling,
    normalize_text
)

# Instructs pytest that all tests in this file are asynchronous
pytestmark = pytest.mark.asyncio

# --- UNIT TESTS ---

async def test_normalization_evasion():
    """
    Verifies that the system correctly strips invisible Unicode characters 
    (Zero-Width) used by attackers to bypass keyword filters.
    """
    # The word 'urgent' with zero-width characters injected between letters
    obfuscated = "u\u200br\u200bg\u200be\u200bn\u200bt" 
    assert normalize_text(obfuscated) == "urgent"

async def test_brand_impersonation_complex():
    """
    Tests detection of complex impersonation involving both 
    lookalike characters (0 for o) and hyphenation.
    """
    # Edge case: g00gle-alert
    result = await analyze_brand_impersonation("security@g00gle-alert.com")
    assert result["score"] > 0
    # Verifies that the reason accurately references the target brand
    assert "google" in result["reasons"][0].lower()

async def test_html_smuggling_detection():
    """
    Tests detection of JavaScript patterns used to build malicious 
    files locally within the browser.
    """
    body = "Click to view: <script>const file = new Blob([data]);</script>"
    result = await detect_html_smuggling(body)
    assert result["score"] >= 45
    assert "smuggling" in result["reasons"][0].lower()

async def test_url_obfuscation_tactics():
    """
    Tests detection of link obfuscation techniques such as 
    raw IP addresses and misleading @ symbols.
    """
    # Testing IP-based destination
    ip_result = await analyze_urls_advanced("http://192.168.1.1/update")
    assert ip_result["score"] >= 50
    
    # Testing misleading @ symbol usage
    at_result = await analyze_urls_advanced("https://portal.office.com@evil-site.net")
    assert at_result["score"] >= 40

# --- INTEGRATION TESTS ---

async def test_complex_phishing_flow():
    """
    Comprehensive integration test simulating a high-sophistication 
    phishing email combining multiple vectors: impersonation, 
    psychological pressure, hidden links, and malicious attachments.
    """
    email_data = {
        "sender": "support@g00gle-security.com", # Impersonation with '0' and hyphens
        "subject": "URGENT: ACCOUNT SUSPENDED",   # Urgency & All-Caps
        "body": "Your l\u200bast payment failed. Update: http://bit.ly/fake", # Invisible chars & shortener
        "auth_results": "pass",
        "attachments": [{"filename": "invoice.pdf.exe"}] # Double extension & dangerous filetype
    }
    
    result = await calculate_risk_score(email_data, db_cursor=None)
    
    # 1. Verify the final verdict
    assert result["verdict"] == "Malicious"
    assert result["score"] >= 75
    
    # 2. Verify that each relevant engine flagged its specific threat
    reasons = [r.lower() for r in result["risk_factors"]]
    
    assert any("impersonation" in r for r in reasons), "Failed to detect Brand Impersonation"
    assert any("financial" in r or "payment" in r or "urgency" in r for r in reasons), "Failed to detect Suspicious Content"
    assert any("url" in r or "shortened" in r for r in reasons), "Failed to detect Malicious Link"
    assert any("attachment" in r or "extension" in r for r in reasons), "Failed to detect Dangerous Attachment"

async def test_legitimate_email():
    """
    Ensures that legitimate emails pass through without 
    false alarms (False Positives).
    """
    email_data = {
        "sender": "colleague@actual-work.com",
        "subject": "Lunch today?",
        "body": "Hey, do you want to grab some food later?",
        "auth_results": "pass"
    }
    result = await calculate_risk_score(email_data, db_cursor=None)
    assert result["verdict"] == "Safe"
    assert result["score"] < 25