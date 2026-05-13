from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from core.analyzer import SecurityAnalyzer
import os

app = FastAPI()
analyzer = SecurityAnalyzer()

app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")

def is_safe_path(path):
    forbidden = ["/etc", "/proc", "/sys", "/data/data/com.termux/files/usr"]
    return not any(path.startswith(p) for p in forbidden)

@app.post("/analyze")
async def analyze_path(data: dict):
    path = data.get('path', '')
    if not path or not is_safe_path(path):
        raise HTTPException(status_code=400, detail="Invalid path")
    results = analyzer.run_bandit(path)
    ai_report = analyzer.get_ai_remediation(results)
    return {"raw_issues_count": len(results), "ai_analysis": ai_report}

@app.post("/upload-analyze")
async def upload_file(file: UploadFile = File(...)):
    safe_name = os.path.basename(file.filename)
    file_path = f"temp_{safe_name}"
    try:
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)
        results = analyzer.run_bandit(file_path)
        ai_report = analyzer.get_ai_remediation(results)
        return {"raw_issues_count": len(results), "ai_analysis": ai_report}
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
