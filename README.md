# 🛡️ Upwind Security Task: AI-Powered Malicious Email Scorer

## 🎯 Project Objective
[cite_start]This project is a Gmail Add-on designed to analyze an opened email and produce a maliciousness score mapped to a clear, explainable verdict[cite: 5]. [cite_start]It utilizes an asynchronous backend service to process email metadata and content through a Hybrid Detection Architecture, focusing on security awareness and clean design[cite: 26].

---

## 🏗️ System Architecture
The solution is built using a decoupled architecture to separate the user interface from the heavy processing logic:

1. [cite_start]**Frontend (Google Workspace Add-on):** A lightweight Apps Script interface that runs natively inside Gmail[cite: 24]. It extracts necessary metadata (sender, headers, body) and presents the final security report without interrupting the user's workflow.
2. [cite_start]**Backend (FastAPI - Python):** An asynchronous orchestration layer[cite: 25]. Instead of sequential scanning, the system uses `asyncio` to fire multiple heuristic analysis engines concurrently to minimize latency.
3. **The Logic Pipeline (Hybrid Detection):**
   * **Tier 1 (Deterministic Heuristics):** Rapid, rule-based checks for known technical anomalies (e.g., typosquatting, suspicious TLDs, long URLs).
   * **Tier 2 (Semantic AI Analysis):** Triggered conditionally (if the heuristic score falls in the "Grey Zone" of 30-65) to evaluate intent, urgency, and social engineering context.

---

## ⚖️ Design Decisions & Trade-offs
[cite_start]As prioritization and design choices are a core part of this evaluation[cite: 8], here is the rationale behind the key architectural decisions:

* **Hybrid Architecture & Dynamic Triggering (Performance vs. Depth):**
  * *Decision:* Relying on deterministic heuristics for the baseline scan, but dynamically triggering the **Gemini 2.5 Flash API** only if the initial score is ambiguous.
  * *Rationale:* LLMs are unmatched at detecting zero-day social engineering, but they introduce latency and API costs. Static rules are extremely fast but lack contextual awareness. Dynamic triggering provides the optimal balance.
* **Asynchronous Orchestration (Latency vs. Complexity):**
  * *Decision:* Utilizing `asyncio` in the FastAPI backend to run multiple scanning engines concurrently.
  * *Rationale:* While async programming increases backend complexity, sequential scanning would cause unacceptable delays in a Gmail UI context. Concurrency ensures a near-instant user experience.
* **Explainability Over Opaque Scoring (Transparency):**
  * *Decision:* The API returns a deduplicated array of specific `Risk Factors` alongside the final score.
  * [cite_start]*Rationale:* Returning detailed reasons requires more complex backend aggregation, but it strictly aligns with the "Explainability" requirement[cite: 17]. It empowers the user to understand *why* an email is dangerous.
* **User-Managed Blacklist (MVP Flat File vs. Relational DB):**
  * *Decision:* Implementing the user blacklist capability via a local `user_blacklist.txt` file instead of deploying a full SQL database.
  * [cite_start]*Rationale:* Prioritizes a clean, easily deployable Proof of Concept (PoC) over heavy infrastructure overhead, successfully demonstrating the core logic: user-defined policies are absolute and instantly override algorithmic decisions[cite: 18].

---

## ⚙️ Implemented Features & Capabilities

* [cite_start]**Email Content and Metadata Analysis:** Analyzes headers, metadata, and body content to identify suspicious patterns[cite: 15], including URL obfuscation and visual homograph attacks via fuzzy string matching (Levenshtein distance).
* [cite_start]**Dynamic Enrichment via External APIs:** Fetches intelligence data dynamically using the **Gemini 2.5 Flash API** [cite: 12, 13] to perform cognitive reasoning and catch phishing attempts that bypass static blacklists.
* [cite_start]**Risk Scoring and Verdict:** Aggregates signals into a single risk score (0-100) mapped to a clear verdict[cite: 16]: `Safe` (0-34), `Suspicious` (35-74), or `Malicious` (75-100).
* [cite_start]**Explainability:** Clearly presents why the email received its score and which signals contributed[cite: 17].
* [cite_start]**User-Managed Blacklist:** Allows users to define personal blacklist entries that immediately force a 100/100 malicious score for designated senders[cite: 18].

---

## 🧪 Testing & Quality Assurance
* **Gold Dataset:** The system was benchmarked against a curated dataset of test samples, including known phishing campaigns and legitimate corporate communications.
* **Adversarial Testing:** Simulated evasion tactics such as URL obfuscation and HTML smuggling to verify engine robustness and reduce False Positives.

---

## 🚧 Limitations & Future Roadmap
[cite_start]This solution acts as a Proof of Concept and does not need to be production-ready[cite: 9]. 
* [cite_start]**Attachment Analysis:** The current architecture includes a stub for attachment analysis, but safely analyzing payloads [cite: 14] requires future integration with a dedicated sandboxing environment.
* [cite_start]**Management Console:** Providing a simple interface to manage settings, preferences, and policies [cite: 22][cite_start], as well as tracking previous scans[cite: 21], is currently limited. Future iterations will include a full Database (SQL) and a dedicated frontend dashboard.

---

## 🚀 Setup & Execution

### Prerequisites
* Python 3.9+
* Google Workspace Account

### Installation
```bash
# 1. Clone the repository and install dependencies
pip install -r requirements.txt

# 2. Configure Environment variables
# Create a .env file based on .env.example and add your GEMINI_API_KEY
cp .env.example .env

# 3. Run the Backend Service
uvicorn main:app --reload

# 4. Run the automated test suite (Optional)
python test_api.py