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
    Comprehensive URL analysis engine. Detects phishing indicators including:
    - High-risk TLDs
    - IP-based destinations
    - Punycode (Homograph attacks)
    - URL Shorteners
    - Obfuscation techniques (Long URLs, excessive subdomains, '@' usage)
    """
    score = 0
    reasons = []
    
    # Regex to extract URLs (handles http, https, and www)
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, body)
    
    if not urls:
        return {"score": 0, "reasons": []}
        
    for url in urls:
        url_lower = url.lower()
        # Extract components safely (e.g., domain, suffix, subdomain)
        ext = tldextract.extract(url_lower)
        full_domain = f"{ext.domain}.{ext.suffix}"
        
        # 1. High-Risk TLD Check
        malicious_tlds = ["xyz", "top", "click", "pw", "link", "zip", "tk", "date", "cc"]
        if ext.suffix in malicious_tlds:
            score += 30
            reasons.append(f"Suspicious URL: Link leads to a high-risk TLD (.{ext.suffix}).")

        # 2. Direct IP Address Detection
        # Attackers use IPs to bypass domain-based reputation filters
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ext.domain):
            score += 50
            reasons.append(f"Critical: URL uses a raw IP address ({ext.domain}) instead of a domain name.")
            
        # 3. Homograph Attack Detection (Punycode)
        # Using lookalike characters (e.g., 'xn--' prefix)
        if "xn--" in url_lower:
            score += 65
            reasons.append("Danger: Punycode detected (Possible Homograph/lookalike domain attack).")
            
        # 4. URL Shortener Detection
        shorteners = ["bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "rebrand.ly"]
        if any(s in url_lower for s in shorteners):
            score += 20
            reasons.append("Warning: Email contains a shortened URL used to mask the final destination.")

        # --- ADVANCED EDGE CASES (Obfuscation) ---

        # 5. URL Length Analysis
        # Phishing URLs are often extremely long to hide the actual domain from the user's view
        if len(url) > 150:
            score += 20
            reasons.append("Warning: URL is suspiciously long (common obfuscation tactic).")

        # 6. Excessive Subdomains
        # e.g., 'paypal.com.secure.login.update.account-verify.net'
        if url.count('.') > 4:
            score += 25
            reasons.append("Suspicious: URL contains an excessive number of subdomains.")

        # 7. Misleading '@' Symbol
        # Browsers sometimes ignore everything before the '@' in a URL
        # e.g., 'https://www.google.com@malicious-site.com'
        path_part = url_lower.split("//")[-1] if "//" in url_lower else url_lower
        if "@" in path_part:
            score += 45
            reasons.append("Critical: URL contains '@' symbol, a technique used to mislead users about the destination.")

    # Cap the score for this specific module at 100
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
    The central orchestrator of the security engine. 
    It runs all analysis modules in parallel (Concurrency) and aggregates 
    the final risk score and verdict based on multiple security vectors.
    """
    # Extracting data from the payload (with safe defaults)
    sender = email_data.get("sender", "")
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    attachments = email_data.get("attachments", [])
    
    # Defining the concurrent analysis tasks
    # Using asyncio.gather allows us to run these without waiting for each other,
    # significantly reducing the latency for the Gmail Add-on user.
    tasks = [
        analyze_sender_trust(email_data, db_cursor),      # DB & Auth (SPF/DKIM)
        analyze_content_heuristics(subject, body),        # Textual patterns
        analyze_brand_impersonation(sender),             # Typosquatting/Fuzzy Matching
        analyze_urls_advanced(body),                      # Malicious links/IPs/Punycode
        analyze_attachments(attachments)                  # Malicious file extensions/Tactic detection
    ]
    
    # Executing all security engines in parallel
    results = await asyncio.gather(*tasks)
    
    # Initializing aggregation variables
    total_score = 0
    risk_factors = []
    
    # Aggregating results from all engines
    for res in results:
        total_score += res["score"]
        risk_factors.extend(res["reasons"])
    
    # Normalizing the score: Even if multiple engines find threats, 
    # the maximum risk is capped at 100%.
    total_score = min(total_score, 100)
    
    # Verdict Logic: Mapping the numerical score to a human-readable verdict.
    # High Score (>= 75): Definite threat detected.
    # Mid Score (>= 35): Suspicious activity, requires user caution.
    # Low Score (< 35): Likely safe.
    if total_score >= 75:
        verdict = "Malicious"
    elif total_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        # Providing feedback for safe emails to improve User Experience (UX)
        if not risk_factors:
            risk_factors = ["All heuristic and technical security checks passed."]

    # Return the structured response required by the API
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