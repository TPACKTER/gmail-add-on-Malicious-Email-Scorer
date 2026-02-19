import asyncio

# --- SENDER TRUST ANALYSIS ---

async def analyze_sender_trust(email_data: dict, cursor) -> dict:
    """
    Analyzes sender identity based on technical reputation, 
    database blacklists, and protocol authentication (SPF/DKIM).
    """
    score = 0
    reasons = []
    
    sender = email_data.get("sender", "").lower()
    auth_results = email_data.get("auth_results", "pass").lower()
    
    # 1. Email Authentication Verification (SPF/DKIM/DMARC)
    # These results are typically extracted from the 'Authentication-Results' header
    if "fail" in auth_results:
        score += 85  # High risk: Identity spoofing detected
        reasons.append("Critical: Sender authentication failed (SPF/DKIM). Potential spoofing.")
    elif "softfail" in auth_results:
        score += 40
        reasons.append("Warning: Inconsistent sender authentication (SPF Softfail).")

    # 2. Personal Blacklist Verification
    if cursor:
        cursor.execute("SELECT email FROM blacklist WHERE email=?", (sender,))
        if cursor.fetchone():
            # Immediate high risk for manually blacklisted entities
            return {"score": 100, "reasons": [f"Sender {sender} is in your personal blacklist."]}

    # 3. Domain Reputation Analysis
    # Identifying high-risk Top-Level Domains (TLDs) frequently used in phishing
    suspicious_tlds = [".xyz", ".tk", ".top", ".info", ".click", ".loan"]
    if any(sender.endswith(tld) for tld in suspicious_tlds):
        score += 30
        reasons.append(f"Sender is using a high-risk domain extension ({sender.split('.')[-1]}).")

    return {"score": min(score, 100), "reasons": reasons}


# --- CONTENT HEURISTICS ENGINE ---

async def analyze_content_heuristics(subject: str, body: str) -> dict:
    """
    Performs static analysis on the email's text to detect 
    social engineering patterns and phishing indicators.
    """
    score = 0
    reasons = []
    full_text = f"{subject} {body}".lower()
    
    # Trigger words related to urgency and psychological manipulation
    urgency_map = {
        "urgent": 15, "immediate action": 20, "suspended": 25, 
        "verify your account": 25, "action required": 15, "unauthorized access": 20
    }
    for trigger, weight in urgency_map.items():
        if trigger in full_text:
            score += weight
            reasons.append(f"Detected urgency trigger: '{trigger}'.")

    # Keywords related to sensitive data and financial fraud
    sensitive_keywords = ["invoice", "bank account", "password", "login", "wire transfer", "payment"]
    for word in sensitive_keywords:
        if word in full_text:
            score += 15
            reasons.append(f"Sensitive keyword detected: '{word}'.")

    # Structural and formatting anomalies
    if subject and subject.isupper() and len(subject) > 5:
        score += 20
        reasons.append("Aggressive formatting (Subject line in ALL CAPS).")
        
    if "!!!" in full_text:
        score += 10
        reasons.append("Excessive use of exclamation marks (Panic inducement).")

    return {"score": min(score, 100), "reasons": reasons}


# --- THE ORCHESTRATOR ---

async def calculate_risk_score(email_data: dict, db_cursor=None, *args, **kwargs) -> dict:
    """
    Coordinates the scanning process by running analysis modules 
    concurrently and aggregating the final risk assessment.
    """
    # Execute analysis tasks in parallel for optimal performance (Concurrency)
    trust_task = analyze_sender_trust(email_data, db_cursor)
    content_task = analyze_content_heuristics(email_data.get("subject", ""), email_data.get("body", ""))
    
    results = await asyncio.gather(trust_task, content_task)
    trust_res, content_res = results

    # Score aggregation and limit capping
    total_score = min(trust_res["score"] + content_res["score"], 100)
    risk_factors = trust_res["reasons"] + content_res["reasons"]
    
    # Categorize verdict based on the total score
    if total_score >= 75:
        verdict = "Malicious"
    elif total_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        if not risk_factors:
            risk_factors = ["All security heuristics passed. No threats detected."]

    return {
        "score": total_score,
        "verdict": verdict,
        "risk_factors": risk_factors
    }