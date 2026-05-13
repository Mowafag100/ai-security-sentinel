from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from core.analyzer import SecurityAnalyzer
import os
import secrets

app = FastAPI()
analyzer = SecurityAnalyzer()

# المجلد المسموح بفحصه فقط
BASE_TARGET = os.path.join(os.getcwd(), "allowed_targets")
os.makedirs(BASE_TARGET, exist_ok=True)
MAX_FILE_SIZE = 1_000_000  # 1 MB

app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")

def get_safe_path(user_path):
    # تحويل المسار لمسار مطلق والتحقق من بقائه داخل BASE_TARGET
    safe_path = os.path.abspath(os.path.join(BASE_TARGET, user_path))
    if not safe_path.startswith(BASE_TARGET):
        return None
    return safe_path

@app.post("/analyze")
async def analyze_path(data: dict):
    target = data.get('path', '')
    safe_path = get_safe_path(target)
    
    if not safe_path or not os.path.exists(safe_path):
        raise HTTPException(status_code=400, detail="Invalid path or access denied")
        
    results = analyzer.run_bandit(safe_path)
    ai_report = analyzer.get_ai_remediation(results)
    return {"raw_issues_count": len(results), "ai_analysis": ai_report}

@app.post("/upload-analyze")
async def upload_file(file: UploadFile = File(...)):
    random_suffix = secrets.token_hex(4)
    safe_name = f"upload_{random_suffix}_{os.path.basename(file.filename)}"
    file_path = os.path.join(BASE_TARGET, safe_name)
    
    try:
        # قراءة محددة للحجم لمنع DoS
        content = await file.read(MAX_FILE_SIZE + 1)
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large (Max 1MB)")
            
        with open(file_path, "wb") as f:
            f.write(content)
        
        results = analyzer.run_bandit(file_path)
        ai_report = analyzer.get_ai_remediation(results)
        return {"raw_issues_count": len(results), "ai_analysis": ai_report}
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
