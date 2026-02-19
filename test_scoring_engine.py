import pytest
import asyncio
from scoring_engine import calculate_risk_score, analyze_urls_advanced, analyze_brand_impersonation

# Since our functions are asynchronous, we need to mark the tests accordingly
pytestmark = pytest.mark.asyncio

async def test_brand_impersonation_detection():
    """Test if the fuzzy matching correctly identifies typosquatting."""
    # Test a clear imitation
    result = await analyze_brand_impersonation("support@paypa1.com")
    assert result["score"] > 0
    assert "paypal" in result["reasons"][0].lower()

    # Test the exact legitimate brand (should not trigger a penalty)
    result_legit = await analyze_brand_impersonation("support@paypal.com")
    assert result_legit["score"] == 0

async def test_suspicious_url_detection():
    """Test if malicious URLs are identified."""
    body_with_ip = "Click here: http://192.168.1.1/login"
    result = await analyze_urls_advanced(body_with_ip)
    assert result["score"] >= 50
    assert "IP address" in result["reasons"][0]

    body_with_bad_tld = "Visit my site: http://malicious.zip"
    result_tld = await analyze_urls_advanced(body_with_bad_tld)
    assert result_tld["score"] >= 30

async def test_full_orchestrator_malicious():
    """Integration test: Check if a multi-threat email returns a Malicious verdict."""
    email_data = {
        "sender": "security@g00gle-alert.com", # Typosquatting
        "subject": "URGENT ACTION REQUIRED",    # Urgency & Caps
        "body": "Your account is suspended. Login here: http://bit.ly/fake", # Shortened URL
        "auth_results": "fail",                 # Auth failure
        "attachments": [{"filename": "invoice.pdf.exe"}] # Double extension
    }
    
    # We pass None for the cursor for this test
    result = await calculate_risk_score(email_data, db_cursor=None)
    
    assert result["score"] == 100
    assert result["verdict"] == "Malicious"
    assert len(result["risk_factors"]) > 3

async def test_safe_email():
    """Ensure a normal email stays safe."""
    email_data = {
        "sender": "mom@gmail.com",
        "subject": "Dinner tonight?",
        "body": "Hey honey, want to eat pizza at 7?",
        "auth_results": "pass"
    }
    result = await calculate_risk_score(email_data, db_cursor=None)
    assert result["verdict"] == "Safe"
    assert result["score"] < 20