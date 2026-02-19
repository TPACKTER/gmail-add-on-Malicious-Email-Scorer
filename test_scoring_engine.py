import pytest
import asyncio
from scoring_engine import (
    calculate_risk_score, 
    analyze_urls_advanced, 
    analyze_brand_impersonation,
    detect_html_smuggling,
    normalize_text,
    validate_arc_chain
)

# Set pytest-asyncio to handle all tests in this file
pytestmark = pytest.mark.asyncio

# --- UNIT TESTS ---

async def test_normalization_evasion():
    """
    Verifies that the engine strips invisible Unicode characters (Zero-Width)
    used to bypass keyword-based filters.
    """
    # The word 'urgent' with zero-width characters (\u200b) injected
    obfuscated = "u\u200br\u200bg\u200be\u200bn\u200bt" 
    assert normalize_text(obfuscated) == "urgent"

async def test_brand_impersonation_logic():
    """
    Tests detection of complex brand impersonation, including:
    1. Homoglyphs (g00gle)
    2. Hyphenated domains (google-security)
    """
    # Test case: g00gle-alert.com should be identified as google
    result = await analyze_brand_impersonation("security@g00gle-alert.com")
    assert result["score"] > 0
    assert "google" in result["reasons"][0].lower()

async def test_html_smuggling_detection():
    """
    Detects JavaScript patterns used to locally construct malicious payloads.
    """
    body = "Click to view: <script>const file = new Blob([data]);</script>"
    result = await detect_html_smuggling(body)
    assert result["score"] >= 45
    assert "smuggling" in result["reasons"][0].lower()

async def test_url_obfuscation():
    """
    Tests detection of IP-based URLs and misleading @ symbols.
    """
    # Raw IP check
    ip_result = await analyze_urls_advanced("http://192.168.1.1/login")
    assert ip_result["score"] >= 50
    
    # Misleading @ check
    at_result = await analyze_urls_advanced("https://portal.office.com@evil-site.net")
    assert at_result["score"] >= 40

async def test_arc_logic_standalone():
    """
    Verifies that ARC provides a strong discount ONLY when a trusted 
    sealer like google.com is identified.
    """
    email_data = {
        "auth_results": "dkim=fail",
        "arc_results": "arc=pass (sealed by google.com)" # Added trusted sealer
    }
    result = await validate_arc_chain(email_data)
    # Now it should match the high discount (-60 or -40 depending on your engine's weight)
    # If you set it to -60 in the engine, change the assert below to -60
    assert result["score"] == -60

# --- INTEGRATION TESTS ---

async def test_complex_phishing_flow():
    """
    Simulates complex phishing. Updated to match exact keyword reasons.
    """
    email_data = {
        "sender": "support@g00gle-security.com",
        "subject": "URGENT: ACCOUNT SUSPENDED",
        "body": "Your l\u200bast payment failed. Update here: http://bit.ly/fake",
        "auth_results": "pass",
        "attachments": [{"filename": "invoice.pdf.exe"}]
    }
    
    result = await calculate_risk_score(email_data, db_cursor=None)
    assert result["verdict"] == "Malicious"
    
    reasons = [r.lower() for r in result["risk_factors"]]
    assert any("impersonation" in r for r in reasons)
    assert any(x in " ".join(reasons) for x in ["financial", "payment", "risk", "urgency"])

async def test_arc_prevents_false_positive():
    """
    Ensures forwarded emails from trusted sources are marked as Safe.
    """
    forwarded_email = {
        "sender": "newsletter@trusted-source.com",
        "subject": "Weekly Update",
        "body": "Here is your news content.",
        "auth_results": "dkim=fail",
        "arc_results": "arc=pass (sealed by microsoft.com)", # Added trusted sealer
        "attachments": []
    }
    
    result = await calculate_risk_score(forwarded_email)
    
    # With the -60 discount for Microsoft, the score will drop significantly
    assert result["verdict"] == "Safe"
    assert any("ARC" in r for r in result["risk_factors"])

async def test_legitimate_email():
    """
    Ensures normal emails pass without false alarms.
    """
    email_data = {
        "sender": "mom@gmail.com",
        "subject": "Dinner?",
        "body": "Do you want pizza tonight?",
        "auth_results": "pass"
    }
    result = await calculate_risk_score(email_data, db_cursor=None)
    assert result["verdict"] == "Safe"
    assert result["score"] < 25