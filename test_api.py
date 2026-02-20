import requests
import json

BASE_URL = "http://127.0.0.1:8000/api/v1/analyze"

def test_email(description, sender, subject, body):
    print(f"\n--- Testing: {description} ---")
    payload = {
        "sender": sender,
        "subject": subject,
        "body": body,
        "attachments": [],
        "auth_results": "pass"
    }
    
    try:
        response = requests.post(BASE_URL, json=payload)
        if response.status_code == 200:
            result = response.json()
            print(f"Verdict: {result['verdict']}")
            print(f"Score:   {result['score']}/100")
            print("Risk Factors:")
            for factor in result['risk_factors']:
                print(f" - {factor}")
        else:
            print(f"Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    # Case 1: High-Risk Phishing
    test_email(
        "Urgent Phishing Attempt",
        "Security Alert <alert-99@verify-cl0ud-safety.biz.ua>",
        "URGENT: Your account has been suspended",
        "Dear user, we detected unusual activity. Please click here to verify: http://bit.ly/fake-login-302. Failure to act will result in account deletion."
    )

    # Case 2: Legitimate Communication
    test_email(
        "Legitimate Work Email",
        "Sivan Yaron <sivan@place-il.org>",
        "Project Update: Q1 Goals",
        "Hi Tamar, let's meet tomorrow to discuss the AI integration project. See you then!"
    )