from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import database

# 1. THE CHANGE: We force Python to find the exact function right now
from scoring_engine import calculate_risk_score 

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
        # 2. THE CHANGE: We call the function directly now
        result = await calculate_risk_score(email.dict(), cursor)
        
        # Save the result to the History table 
        cursor.execute(
            "INSERT INTO scan_history (sender, subject, score, verdict) VALUES (?, ?, ?, ?)", 
            (email.sender, email.subject, result["score"], result["verdict"])
        )
        conn.commit()
        
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