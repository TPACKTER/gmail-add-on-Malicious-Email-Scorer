from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import database
import scoring_engine  # This imports the engine we just talked about

app = FastAPI(title="Malicious Email Scorer API")

# Initialize the database tables when the server starts
database.init_db()

# --- 1. DATA MODELS (The Contract) ---
class EmailPayload(BaseModel):
    sender: str
    subject: str
    body: str
    domains: Optional[List[str]] = []
    hashes: Optional[List[str]] = []

class ScanResult(BaseModel):
    score: int
    verdict: str
    risk_factors: List[str]

# --- 2. ENDPOINTS ---
@app.post("/api/v1/analyze", response_model=ScanResult)
async def analyze_email(email: EmailPayload):
    print(f"Incoming scan request for sender: {email.sender}")
    
    conn = database.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Fire up the asynchronous scoring engine
        # We pass the email data as a dictionary so the engine can process it
        result = await scoring_engine.calculate_risk_score(email.dict(), cursor)
        
        # 2. Save the result to the History table 
        cursor.execute(
            "INSERT INTO scan_history (sender, subject, score, verdict) VALUES (?, ?, ?, ?)", 
            (email.sender, email.subject, result["score"], result["verdict"])
        )
        conn.commit()
        
        # 3. Return the exact reasons and score back to Gmail [cite: 17]
        return ScanResult(**result)
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        # Always close the database connection
        conn.close()

@app.get("/")
def health_check():
    return {"status": "The Threat Engine is Online."}