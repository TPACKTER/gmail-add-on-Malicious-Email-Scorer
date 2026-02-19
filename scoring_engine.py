import asyncio
import re
import tldextract
from thefuzz import fuzz

# --- 1. BRAND PROTECTION (Typosquatting Detection) ---

async def analyze_brand_impersonation(sender_email: str) -> dict:
    """
    Detects if the sender domain is a 'lookalike' of a trusted brand.
    Uses Fuzzy String Matching to identify Typosquatting.
    """
    score = 0
    reasons = []
    
    # Extract the core domain (e.g., 'paypa1' from 'support@paypa1.com')
    extracted = tldextract.extract(sender_email.lower())
    domain = extracted.domain
    
    # High-value targets for impersonation
    trusted_brands = ["google", "microsoft", "netflix", "paypal", "apple", "amazon", "facebook", "upwind"]
    
    for brand in trusted_brands:
        similarity = fuzz.ratio(domain, brand)
        
        # If similarity is high but NOT an exact match (e.g., 'g00gle')
        if 80 <= similarity < 100:
            score += 65
            reasons.append(f"Brand Impersonation: Domain '{domain}' is suspiciously similar to '{brand}'.")
            break 
            
    return {"score": score, "reasons": reasons}


# --- 2. ADVANCED URL ANALYSIS ---

async def analyze_urls_advanced(body: str) -> dict:
    """
    Scans the email body for URLs and analyzes them for phishing indicators.
    """
    score = 0
    reasons = []
    
    # Extract URLs using Regex
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, body)
    
    if not urls:
        return {"score": 0, "reasons": []}
        
    for url in urls:
        url_lower = url.lower()
        ext = tldextract.extract(url_lower)
        
        # A. Check for suspicious/malicious TLDs
        malicious_tlds = ["xyz", "top", "click", "pw", "link", "zip", "tk"]
        if ext.suffix in malicious_tlds:
            score += 30
            reasons.append(f"Suspicious URL: Link leads to a high-risk TLD (.{ext.suffix}).")

        # B. Detect IP-based URLs (Common in phishing to bypass domain blacklists)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ext.domain):
            score += 50
            reasons.append("Critical: URL uses a raw IP address instead of a domain name.")
            
        # C. Detect Homograph Attacks (Punycode)
        if "xn--" in url_lower:
            score += 60
            reasons.append("Danger: Punycode detected (Possible lookalike domain attack).")
            
        # D. Detect URL Shorteners
        shorteners = ["bit.ly", "t.co", "tinyurl.com", "is.gd"]
        if any(s in url_lower for s in shorteners):
            score += 20
            reasons.append("Warning: Email contains a shortened URL to hide the final destination.")

    return {"score": min(score, 100), "reasons": reasons}


# --- 3. SENDER TRUST & AUTHENTICATION ---

async def analyze_sender_trust(email_data: dict, cursor) -> dict:
    """
    Verifies sender reputation using internal blacklists and technical headers (SPF/DKIM).
    """
    score = 0
    reasons = []
    
    sender = email_data.get("sender", "").lower()
    auth_results = email_data.get("auth_results", "pass").lower()
    
    # 1. Technical Authentication (Mocking SPF/DKIM check)
    if "fail" in auth_results:
        score += 85
        reasons.append("Critical: Sender failed identity authentication (SPF/DKIM).")
    
    # 2. Database Blacklist Lookup
    if cursor:
        cursor.execute("SELECT email FROM blacklist WHERE email=?", (sender,))
        if cursor.fetchone():
            return {"score": 100, "reasons": [f"Sender {sender} is manually blacklisted."]}

    return {"score": min(score, 100), "reasons": reasons}


# --- 4. CONTENT HEURISTICS ---

async def analyze_content_heuristics(subject: str, body: str) -> dict:
    """
    Performs static text analysis for social engineering triggers.
    """
    score = 0
    reasons = []
    full_text = f"{subject} {body}".lower()
    
    # Psychological triggers
    urgency_keywords = ["urgent", "immediate action", "suspended", "verify your account", "action required"]
    for word in urgency_keywords:
        if word in full_text:
            score += 20
            reasons.append(f"Urgency trigger detected: '{word}'.")

    # Financial/Sensitive data triggers
    sensitive_keywords = ["invoice", "bank account", "password", "wire transfer", "payment declined"]
    for word in sensitive_keywords:
        if word in full_text:
            score += 15
            reasons.append(f"Sensitive keyword detected: '{word}'.")

    # Formatting red flags
    if subject and subject.isupper() and len(subject) > 5:
        score += 20
        reasons.append("Aggressive formatting (Subject in ALL CAPS).")

    return {"score": min(score, 100), "reasons": reasons}


# --- 5. THE ORCHESTRATOR ---

async def calculate_risk_score(email_data: dict, db_cursor=None, *args, **kwargs) -> dict:
    """
    Orchestrates all specialized security engines concurrently.
    """
    sender = email_data.get("sender", "")
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    
    # Run all analysis tasks in parallel for performance
    tasks = [
        analyze_sender_trust(email_data, db_cursor),
        analyze_content_heuristics(subject, body),
        analyze_brand_impersonation(sender),
        analyze_urls_advanced(body)
    ]
    
    results = await asyncio.gather(*tasks)
    
    # Aggregate results and cap the total score
    total_score = sum(res["score"] for res in results)
    total_score = min(total_score, 100)
    
    risk_factors = []
    for res in results:
        risk_factors.extend(res["reasons"])
    
    # Final Verdict Logic
    if total_score >= 75:
        verdict = "Malicious"
    elif total_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        if not risk_factors:
            risk_factors = ["No threats detected by the security engines."]

    return {
        "score": total_score,
        "verdict": verdict,
        "risk_factors": risk_factors
    }

async def analyze_attachments(attachments: list) -> dict:
    """
    Analyzes email attachments for malicious indicators like dangerous extensions 
    or double extensions (e.g., .pdf.exe).
    """
    score = 0
    reasons = []
    
    if not attachments:
        return {"score": 0, "reasons": []}
        
    dangerous_extensions = ["exe", "vbs", "scr", "js", "bat", "cmd", "msi", "ps1"]
    
    for attachment in attachments:
        filename = attachment.get("filename", "").lower()
        if not filename: continue
        
        # 1. Check for dangerous extensions
        extension = filename.split(".")[-1]
        if extension in dangerous_extensions:
            score += 60
            reasons.append(f"Danger: Attachment '{filename}' has a high-risk executable extension.")
            
        # 2. Check for double extensions (e.g., invoice.pdf.exe)
        if len(filename.split(".")) > 2:
            score += 40
            reasons.append(f"Suspicious: Attachment '{filename}' uses a double extension (obfuscation tactic).")
            
    return {"score": min(score, 100), "reasons": reasons}