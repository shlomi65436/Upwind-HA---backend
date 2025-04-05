from typing import List
from urllib.parse import urlparse
import uuid
from fastapi import FastAPI, UploadFile, File, Form
import re
import os
import subprocess
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # React's default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ========== Phishing detector ==========

DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com","amazon.com", "paypal.com", "microsoft.com", "apple.com"]
URGENT_KEYWORDS = ["urgent", "immediately", "action required", "verify your account","account suspended", "click below", "password expired", "security alert"]
IP_URL_REGEX = r"http[s]?://\d+\.\d+\.\d+\.\d+"
URL_REGEX = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
LEVENSHTEIN_THRESHOLD = 3

# Helper function to calculate Levenshtein distance
def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

# Phishing detection logic
def detect_phishing(email_content: str) -> List[str]:
    indicators = []
    urls = re.findall(URL_REGEX, email_content)
    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
            
            # Check for IP address in URL
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                indicators.append(f"IP address in URL: {url}")
                continue
            
            # Check for uncommon domains
            is_legitimate = any(legit_domain in domain for legit_domain in DOMAINS)
            if not is_legitimate and domain not in DOMAINS:
                indicators.append(f"Uncommon domain: {url}")
            
        except:
            continue

    # Detect urgent language
    for keyword in URGENT_KEYWORDS:
        if keyword.lower() in email_content.lower():
            indicators.append(f"Urgent language detected: '{keyword}'")

    # Detect spoofed sender addresses 
    spoofed_sender_pattern = r"From:.*<([^>]+)>"
    sender_match = re.search(spoofed_sender_pattern, email_content)
    if sender_match:
        sender_email = sender_match.group(1)
        for suspicious_domain in DOMAINS:
            if 0 < levenshtein_distance(sender_email.split('@')[-1], suspicious_domain) <= LEVENSHTEIN_THRESHOLD:
                indicators.append(f"Spoofed sender address detected: {sender_email}")

    return indicators

@app.post("/detect-phishing/")
async def detect_phishing_endpoint(file: UploadFile = File(...)):
    email_content = await file.read()
    email_text = email_content.decode("utf-8")
    indicators = detect_phishing(email_text)

    if indicators:
        return {
            "message": "Potential phishing attempt detected.",
            "indicators": indicators,
        }
    else:
        return {
            "message": "No phishing indicators detected.",
        }




# ========== MALWARE SANDBOX ==========
UPLOAD_FOLDER = "uploaded_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure upload directory exists

@app.post("/execute/")
async def execute_malware(file: UploadFile = File(...)):
    # Generate a unique filename to avoid overwriting
    unique_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)

    # Save the uploaded file
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Run the Docker-based sandbox
    container_name = "malware_sandbox"

    try:
        # Copy the malware file into the current directory (so Docker can access it)
        subprocess.run(["cp", file_path, os.getcwd()], check=True)

        # Build and run Docker with the malware file
        subprocess.run(["docker", "build", "-t", container_name, "."], check=True)
        subprocess.run([
            "docker", "run", "--rm", "--name", container_name,
            "-v", f"{os.getcwd()}/uploaded_files:/sandbox/malware",
            "-v", f"{os.getcwd()}/reports:/sandbox/reports",
            "--cap-add=NET_ADMIN", 
            "--cap-add=NET_RAW",  # Needed for packet capture
            "--network", "none",  # Start with no network
            "--security-opt", "seccomp=unconfined",
            container_name, unique_filename
        ], check=True)

        report_path = "reports/malware_report.txt"
        if os.path.exists(report_path):
            with open(report_path, "r") as report_file:
                report_content = report_file.read()
            return {"status": "success", "report": report_content}
        else:
            return {"status": "error", "message": "Report not found"}
    
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": str(e)}




# ========== SQL INJECTION SIMULATION ==========
# ====== DATABASE SETUP ======
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create users table (only run once to initialize DB)
def create_users_table():
    with engine.connect() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """))
        conn.execute(text("""
        INSERT OR IGNORE INTO users (username, password) VALUES 
        ('admin', 'password123'),
        ('user', 'letmein')
        """))  # Prepopulate with test users
        conn.commit()

create_users_table()

# ====== VULNERABLE LOGIN ENDPOINT (Allows SQL Injection) ======
@app.post("/sql-injection/test/")
async def test_sql_injection(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        # ⚠️ VULNERABLE QUERY (user input directly inserted into SQL)
        query = text(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        result = db.execute(query).fetchall()

        if result:
            return {"message": "Login successful (VULNERABLE!)"}
        return {"message": "Login failed"}
    finally:
        db.close()

# ====== SECURE LOGIN ENDPOINT (Prevents SQL Injection) ======
@app.post("/sql-injection/secure-test/")
async def secure_sql_injection(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        # ✅ SECURE QUERY (Uses parameterized query)
        query = text("SELECT * FROM users WHERE username=:username AND password=:password")
        result = db.execute(query, {"username": username, "password": password}).fetchall()

        if result:
            return {"message": "Login successful (SECURE)"}
        return {"message": "Login failed"}
    finally:
        db.close()




# # ========== RUN SERVER ==========
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
