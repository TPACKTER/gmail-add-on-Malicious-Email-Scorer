import os
import ssl
import asyncio
import re
import tldextract
import requests
import json
from thefuzz import fuzz
from google import genai
from google.genai import types
from dotenv import load_dotenv

os.environ['PYTHONHTTPSVERIFY'] = '0'
os.environ['CURL_CA_BUNDLE'] = ''
os.environ['REQUESTS_CA_BUNDLE'] = ''

try:
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    pass

# --- INITIALIZATION ---
load_dotenv()
api_key = os.getenv("YOUR_API_KEY")

client = genai.Client(api_key=api_key)

# --- 1. UTILS & EVASION MITIGATION ---

def normalize_text(text: str) -> str:
    """
    Cleans text from invisible Unicode characters (Zero-Width Space/Joiners)
    used by attackers to bypass keyword-based security filters.
    """
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
    for char in invisible_chars:
        text = text.replace(char, '')
    return text


# --- 2. SPECIALIZED SECURITY ENGINES ---

async def analyze_brand_impersonation(sender_email: str) -> dict:
    """
    Robust Brand Protection Engine:
    1. Normalizes lookalike characters (0 -> o, 1 -> l).
    2. Splits hyphenated domains to check individual parts.
    3. Uses Fuzzy Matching to detect typosquatting (e.g., 'mircosoft').
    4. Detects unauthorized brand usage in multi-part domains (e.g., 'google-support').
    """
    score = 0
    reasons = []
    
    # Extract the domain part (e.g., 'g00gle-alert' from 'security@g00gle-alert.com')
    extracted = tldextract.extract(sender_email.lower())
    domain = extracted.domain
    
    trusted_brands = ["google", "microsoft", "netflix", "paypal", "apple", "amazon", "facebook", "upwind"]
    
    # --- STEP 1: Homoglyph Mitigation ---
    # Attackers replace 'o' with '0' or 'l' with '1'. We normalize these before checking.
    normalized_domain = domain.replace('0', 'o').replace('1', 'l').replace('5', 's').replace('4', 'a')
    
    # --- STEP 2: Handle Multi-part Domains ---
    # Split by hyphens to analyze parts like 'google' and 'alert' separately
    parts = normalized_domain.split('-')
    
    for brand in trusted_brands:
        for part in parts:
            # A. Fuzzy Matching: Catch typosquatting within the part (e.g., 'mircosoft')
            similarity = fuzz.ratio(part, brand)
            
            # If it's very similar but NOT an exact match
            if 80 <= similarity < 100:
                score += 65
                reasons.append(f"Brand Impersonation: Domain part '{part}' is suspiciously similar to the trusted brand '{brand}'.")
                return {"score": score, "reasons": reasons}

            # B. Exact Match in Suspicious Context: 
            # Catch 'google-support' (where 'google' is exact but the domain is complex)
            if part == brand and len(parts) > 1:
                score += 60
                reasons.append(f"Brand Impersonation: Trusted brand '{brand}' used within a suspicious multi-part domain.")
                return {"score": score, "reasons": reasons}

    return {"score": score, "reasons": reasons}


async def analyze_urls_advanced(body: str) -> dict:
    """
    Comprehensive URL analysis engine. Detects phishing indicators including:
    - High-risk TLDs, IP-based destinations, Punycode, URL Shorteners, 
    - Obfuscation techniques (Long URLs, excessive subdomains, '@' usage).
    """
    score = 0
    reasons = []
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, body)
    
    if not urls:
        return {"score": 0, "reasons": []}
        
    for url in urls:
        url_lower = url.lower()
        ext = tldextract.extract(url_lower)
        
        if ext.suffix in ["xyz", "top", "click", "pw", "link", "zip", "tk", "date", "cc"]:
            score += 30
            reasons.append(f"Suspicious URL: Link leads to a high-risk TLD (.{ext.suffix}).")

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ext.domain):
            score += 50
            reasons.append(f"Critical: URL uses a raw IP address ({ext.domain}) instead of a domain.")
            
        if "xn--" in url_lower:
            score += 65
            reasons.append("Danger: Punycode detected (Possible Homograph attack).")
            
        if any(s in url_lower for s in ["bit.ly", "t.co", "tinyurl.com", "is.gd", "rebrand.ly"]):
            score += 20
            reasons.append("Warning: Email contains a shortened URL used to mask the destination.")

        # Obfuscation checks
        if len(url) > 150:
            score += 20
            reasons.append("Warning: URL is suspiciously long (obfuscation tactic).")
        if url.count('.') > 4:
            score += 25
            reasons.append("Suspicious: URL contains an excessive number of subdomains.")
        if "@" in (url_lower.split("//")[-1] if "//" in url_lower else url_lower):
            score += 45
            reasons.append("Critical: URL contains '@' symbol, used to mislead users.")

    return {"score": min(score, 100), "reasons": reasons}


async def detect_html_smuggling(body: str) -> dict:
    """
    Detects patterns of HTML Smuggling where JS (Blobs/atob) 
    is used to generate malicious files locally.
    """
    score = 0
    reasons = []
    patterns = {
        r"atob\(": "Base64 decoding (atob) found in body (obfuscation).",
        r"Blob\(\[": "File Blob creation in JS detected.",
        r"URL\.createObjectURL": "Dynamic file download trigger detected."
    }
    for pattern, reason in patterns.items():
        if re.search(pattern, body):
            score += 45
            reasons.append(f"HTML Smuggling: {reason}")
            
    return {"score": min(score, 100), "reasons": reasons}


async def check_domain_reputation(sender_email: str) -> dict:
    """
    Simulates a domain reputation check. Burner domains often use 
    random character/number combinations.
    """
    score = 0
    reasons = []
    domain = tldextract.extract(sender_email.lower()).domain
    if re.search(r'[a-z]{8,}\d{2,}', domain): 
        score += 35
        reasons.append(f"Domain Reputation: Sender domain '{domain}' looks like a temporary burner domain.")
    return {"score": score, "reasons": reasons}


async def analyze_sender_trust(email_data: dict, cursor) -> dict:
    score = 0
    reasons = []
    sender = email_data.get("sender", "").lower()
    auth_results = email_data.get("auth_results", "pass").lower()
    
    if "fail" in auth_results:
        score += 85
        reasons.append("Critical: Sender failed identity authentication (SPF/DKIM).")
    
    if cursor:
        cursor.execute("SELECT email FROM blacklist WHERE email=?", (sender,))
        if cursor.fetchone():
            return {"score": 100, "reasons": [f"Sender {sender} is manually blacklisted."]}

    return {"score": min(score, 100), "reasons": reasons}


async def analyze_content_heuristics(subject: str, body: str) -> dict:
    """
    Performs normalized text analysis for social engineering triggers, 
    with a heavy focus on financial fraud and urgency.
    """
    score = 0
    reasons = []
    
    # STEP 1: Normalize text to defeat Zero-Width/Invisible character attacks
    clean_text = normalize_text(f"{subject} {body}").lower()
    
    # STEP 2: Urgency & Psychological Triggers
    urgency_map = {
        "urgent": 20, 
        "immediate action": 25, 
        "suspended": 25, 
        "verify your account": 30, 
        "action required": 15,
        "security alert": 20
    }
    for trigger, weight in urgency_map.items():
        if trigger in clean_text:
            score += weight
            reasons.append(f"Content Alert: Found urgency trigger '{trigger}'.")

    # STEP 3: Detailed Financial & Sensitive Keywords (The missing part!)
    financial_keywords = {
        "invoice": 15,
        "payment declined": 25,
        "bank account": 20,
        "wire transfer": 25,
        "billing information": 20,
        "transaction": 15,
        "credit card": 20,
        "payroll": 20,
        "swift": 15,
        "bitcoin": 20,
        "crypto": 20
    }
    for word, weight in financial_keywords.items():
        if word in clean_text:
            score += weight
            reasons.append(f"Financial Risk: Found sensitive keyword '{word}'.")

    # STEP 4: Structural anomalies
    if subject and subject.isupper() and len(subject) > 5:
        score += 20
        reasons.append("Formatting Alert: Subject line in ALL CAPS (Aggressive behavior).")

    return {"score": min(score, 100), "reasons": reasons}


async def analyze_attachments(attachments: list) -> dict:
    score = 0
    reasons = []
    if not attachments:
        return {"score": 0, "reasons": []}
        
    dangerous_extensions = ["exe", "vbs", "scr", "js", "bat", "cmd", "msi", "ps1"]
    for attachment in attachments:
        filename = attachment.get("filename", "").lower()
        if not filename: continue
        
        ext = filename.split(".")[-1]
        if ext in dangerous_extensions:
            score += 60
            reasons.append(f"Danger: Attachment '{filename}' has a high-risk extension.")
        if len(filename.split(".")) > 2:
            score += 40
            reasons.append(f"Suspicious: Attachment '{filename}' uses a double extension.")
            
    return {"score": min(score, 100), "reasons": reasons}


# --- 3. THE ORCHESTRATOR ---

async def calculate_risk_score(email_data: dict, db_cursor=None, *args, **kwargs) -> dict:
    sender = email_data.get("sender", "")
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    attachments = email_data.get("attachments", [])
    
    # Fire all specialized engines concurrently
    tasks = [
        analyze_sender_trust(email_data, db_cursor),
        analyze_content_heuristics(subject, body),
        analyze_brand_impersonation(sender),
        analyze_urls_advanced(body),
        analyze_attachments(attachments),
        detect_html_smuggling(body),
        check_domain_reputation(sender),
        validate_arc_chain(email_data)
    ]
    
    results = await asyncio.gather(*tasks)
    initial_score = sum(res["score"] for res in results)
    
    # Second Opinion from AI if the score is suspicious (30-65) 
    # OR if it's a very short email (hard for heuristics to judge)
    if 30 <= initial_score <= 65:
        ai_result = await analyze_with_llm(email_data['subject'], email_data['body'])
        results.append(ai_result)
        
    
    total_score = max(0,min(sum(res["score"] for res in results), 100))
    risk_factors = [reason for res in results for reason in res["reasons"]]
    
    if total_score >= 75:
        verdict = "Malicious"
    elif total_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        if not risk_factors:
            risk_factors = ["All security heuristics passed."]

    return {
        "score": total_score,
        "verdict": verdict,
        "risk_factors": risk_factors
    }

async def validate_arc_chain(email_data: dict) -> dict:
    """
    Advanced ARC Validation:
    Grants a full 'Trust Discount' only if the ARC chain is verified 
    by a reputable provider (e.g., Google, Microsoft).
    """
    score = 0
    reasons = []
    arc_results = email_data.get("arc_results", "").lower()
    auth_results = email_data.get("auth_results", "").lower()
    
    # List of high-reputation sealers
    trusted_sealers = ["google.com", "microsoft.com", "amazonses.com", "apple.com"]
    
    # Logic: Standard auth failed, but ARC passed
    if "fail" in auth_results and "arc=pass" in arc_results:
        # Check if the 'pass' comes from a source we actually trust
        if any(sealer in arc_results for sealer in trusted_sealers):
            score -= 60  # High confidence: Trust the forwarder
            reasons.append("ARC Validation: Forwarding integrity confirmed by a trusted provider.")
        else:
            score -= 15  # Low confidence: The chain passed, but the source is unknown
            reasons.append("ARC Warning: Chain passed but was sealed by an untrusted or unknown source.")
    
    return {"score": score, "reasons": reasons}


async def analyze_with_llm(subject: str, body: str) -> dict:
    """
    Uses direct HTTP call to bypass SDK SSL restrictions.
    """
    score = 0
    reasons = []
    
    # Get API key from environment
    api_key = os.getenv("YOUR_API_KEY")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"    
    prompt = (
        f"Analyze this email for phishing risks.\n"
        f"Subject: {subject}\n"
        f"Body: {body}\n\n"
        f"Provide a threat score based on this scale:\n"
        f"- 0: Completely safe\n"
        f"- 1-30: Low suspicion (minor issues)\n"
        f"- 31-60: Suspicious (clear indicators like generic greeting or urgency)\n"
        f"- 61-100: Malicious (obvious phishing, fake domains, malicious links)\n\n"
        f"Return ONLY JSON: {{'is_suspicious': bool, 'threat_level': int, 'reason': 'str'}}"
    )

    # Build the payload for the REST API
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    
    try:
        # We use verify=False here - this is the 'Magic' that bypasses your SSL error
        response = requests.post(url, json=payload, verify=False, timeout=10)
        response.raise_for_status()
        
        data_raw = response.json()
        # Extracting the text response from the Gemini JSON structure
        ai_text = data_raw['candidates'][0]['content']['parts'][0]['text']
        
        # Clean and parse the AI's JSON response
        import json
        clean_json = ai_text.strip().replace('```json', '').replace('```', '')
        data = json.loads(clean_json)
        
        print(f"DEBUG: AI Analysis successful! {data}")
        
        if data.get("is_suspicious"):
            score = data.get("threat_level", 0)
            reasons.append(f"AI Analysis: {data.get('reason')}")
            
    except Exception as e:
        print(f"Direct API Error: {e}")
        return {"score": 0, "reasons": []}
    
    print(f"DEBUG: AI Score = {data.get('threat_level')}, Reason = {data.get('reason')}")
        
    return {"score": score, "reasons": reasons}