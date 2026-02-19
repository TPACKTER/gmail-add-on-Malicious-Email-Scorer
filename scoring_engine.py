import asyncio
# import httpx  # We will use this later for async API calls to VirusTotal/LLMs

# --- 1. INDIVIDUAL WORKERS (The Signals) ---

async def check_blacklist(sender_email: str, cursor) -> dict:
    """Checks the SQLite database to see if the user blocked this sender."""
    # SAFETY CHECK: If no database is connected yet, skip this test
    if cursor is None:
        return {"score": 0, "reason": None}
        
    # In a real app, this runs a SQL query...
    cursor.execute("SELECT email FROM blacklist WHERE email=?", (sender_email,))
    is_blacklisted = cursor.fetchone() is not None
    
    if is_blacklisted:
        return {"score": 100, "reason": f"Sender {sender_email} is on your custom blacklist."}
    return {"score": 0, "reason": None}

async def analyze_heuristics(subject: str, body: str) -> dict:
    """Fast, rule-based static analysis for urgency and phishing keywords."""
    score = 0
    reasons = []
    urgent_keywords = ["urgent", "password reset", "invoice attached", "immediate action"]
    
    subject_lower = subject.lower()
    for word in urgent_keywords:
        if word in subject_lower:
            score += 20
            reasons.append(f"Subject contains highly suspicious keyword: '{word}'")
            break # Only penalize once for subject
            
    return {"score": score, "reasons": reasons}

async def check_virustotal(domains: list, attachment_hashes: list) -> dict:
    """Dynamic Enrichment via External APIs."""
    # TODO: Implement actual httpx call to VirusTotal API here
    await asyncio.sleep(0.1) # Simulate network delay
    
    # Mock response
    if "suspicious-link.com" in domains:
        return {"score": 50, "reasons": ["A domain in this email is flagged by VirusTotal."]}
    return {"score": 0, "reasons": []}

async def analyze_text_with_ai(body: str) -> dict:
    """Uses an LLM to detect social engineering context."""
    # TODO: Implement API call to OpenAI/HuggingFace here
    await asyncio.sleep(0.2) # Simulate AI processing time
    
    # Mock response
    return {"score": 10, "reasons": ["AI analysis detected mild urgency in the email body."]}


# --- 2. THE ORCHESTRATOR (The Aggregator) ---

    async def calculate_risk_score(email_data: dict, db_cursor=None, *args, **kwargs) -> dict:    """
    Combines all signals into a single risk score mapped to a clear verdict.
    """
    # 1. Fire all workers concurrently!
    blacklist_task = check_blacklist(email_data["sender"], db_cursor)
    heuristics_task = analyze_heuristics(email_data["subject"], email_data["body"])
    virustotal_task = check_virustotal(email_data.get("domains", []), email_data.get("hashes", []))
    ai_task = analyze_text_with_ai(email_data["body"])
    
    # Wait for all of them to finish at the same time
    results = await asyncio.gather(blacklist_task, heuristics_task, virustotal_task, ai_task)
    blacklist_res, heuristics_res, vt_res, ai_res = results

    # 2. Compile the mathematical score
    # We use a simple additive model: $Total Score = \sum (Signal_i)$ capped at 100.
    total_score = 0
    risk_factors = []

    # If blacklisted, it's an immediate 100. Override everything else.
    if blacklist_res["score"] == 100:
        return {
            "score": 100,
            "verdict": "Malicious",
            "risk_factors": [blacklist_res["reason"]]
        }

    # Otherwise, tally up the scores and explanations
    total_score += heuristics_res["score"]
    risk_factors.extend(heuristics_res["reasons"])
    
    total_score += vt_res["score"]
    risk_factors.extend(vt_res["reasons"])
    
    total_score += ai_res["score"]
    risk_factors.extend(ai_res["reasons"])

    # Cap at 100
    total_score = min(total_score, 100)

    # 3. Determine Verdict based on Score
    if total_score >= 70:
        verdict = "Malicious"
    elif total_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        if not risk_factors:
            risk_factors = ["All security checks passed. No threats detected."]

    # Return the clean, explainable JSON
    return {
        "score": total_score,
        "verdict": verdict,
        "risk_factors": risk_factors
    }