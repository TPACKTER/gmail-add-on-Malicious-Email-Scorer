from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import database
from scoring_engine import calculate_risk_score

app = FastAPI(title="Malicious Email Scorer API")

# Initialize the database tables on server startup
database.init_db()

# --- DATA MODELS ---
class EmailPayload(BaseModel):
    sender: str
    subject: str
    body: str
    auth_results: Optional[str] = "pass"
    attachments: Optional[List[dict]] = []
    domains: Optional[List[str]] = []
    hashes: Optional[List[str]] = []

class ScanResult(BaseModel):
    score: int
    verdict: str
    risk_factors: List[str]

class BlacklistEntry(BaseModel):
    email: str

# --- ENDPOINTS ---

@app.post("/api/v1/analyze", response_model=ScanResult)
async def analyze_email(email: EmailPayload):
    """
    Primary endpoint for the Gmail Add-on. 
    It coordinates between the database and the scoring engine.
    """
    print(f"Incoming scan request for sender: {email.sender}")
    
    conn = database.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Fire the asynchronous scoring engine
        # We pass the email data and the database cursor for blacklist lookups
        result = await calculate_risk_score(email.dict(), cursor)
        
        # Log the scan results into the history table
        cursor.execute(
            "INSERT INTO scan_history (sender, subject, score, verdict) VALUES (?, ?, ?, ?)", 
            (email.sender, email.subject, result["score"], result["verdict"])
        )
        conn.commit()
        
        # Return the structured result to the Gmail Add-on
        return ScanResult(**result)
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        # Ensure the database connection is always closed
        conn.close()

@app.post("/api/v1/blacklist/add")
async def add_to_blacklist(email: str):
    """
    Simulates the 'Management Console' action of blocking a sender. 
    """
    with open("user_blacklist.txt", "a") as f:
        f.write(f"\n{email.lower()}")
    return {"message": f"Sender {email} blocked successfully."}

@app.get("/")
def health_check():
    return {"status": "The Threat Engine is Online."}

@app.post("/api/v1/blacklist")
async def add_to_blacklist(entry: BlacklistEntry):
    """
    Adds a specific email address to the local blacklist database.
    This allows the user to manually block suspicious senders.
    """
    conn = database.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if already exists to avoid duplicates
        cursor.execute("SELECT email FROM blacklist WHERE email=?", (entry.email.lower(),))
        if cursor.fetchone():
            return {"message": f"Email {entry.email} is already in the blacklist."}
            
        cursor.execute("INSERT INTO blacklist (email) VALUES (?)", (entry.email.lower(),))
        conn.commit()
        print(f"Successfully blacklisted: {entry.email}")
        return {"message": f"Successfully added {entry.email} to blacklist."}
        
    except Exception as e:
        print(f"Error updating blacklist: {e}")
        raise HTTPException(status_code=500, detail="Failed to update blacklist.")
    finally:
        conn.close()

@app.get("/api/v1/blacklist")
async def get_blacklist():
    """
    Returns the current list of blacklisted emails.
    """
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM blacklist")
    emails = [row[0] for row in cursor.fetchall()]
    conn.close()
    return {"blacklisted_emails": emails}

async def test_arc_prevents_false_positive():
    forwarded_email = {
        "sender": "newsletter@trusted-source.com",
        "subject": "Weekly Update",
        "body": "Here is your news.",
        "auth_results": "dkim=fail",
        "arc_results": "arc=pass (google.com)",
        "attachments": []
    }
    
    result = await calculate_risk_score(forwarded_email)
    assert result["verdict"] == "Safe"

    