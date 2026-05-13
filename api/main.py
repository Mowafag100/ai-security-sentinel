from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from core.analyzer import SecurityAnalyzer
from fastapi.responses import HTMLResponse
import subprocess, json, os

app = FastAPI()
analyzer = SecurityAnalyzer()

class ScanRequest(BaseModel):
    path: str

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    with open("dashboard/index.html", "r") as f:
        return f.read()

@app.post("/analyze")
async def analyze_repository(request: ScanRequest):
    try:
        result = subprocess.run(["bandit", "-r", request.path, "-f", "json"], capture_output=True, text=True)
        report = analyzer.generate_remediation_plan(result.stdout)
        return {"raw_issues_count": len(json.loads(result.stdout).get("results", [])), "ai_analysis": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload-analyze")
async def upload_and_analyze(file: UploadFile = File(...)):
    try:
        # حفظ الملف المرفوع مؤقتاً
        file_location = f"temp_{file.filename}"
        with open(file_location, "wb+") as file_object:
            file_object.write(file.file.read())
        
        # فحص الملف أمنياً
        result = subprocess.run(["bandit", file_location, "-f", "json"], capture_output=True, text=True)
        
        # تحليل AI
        report = analyzer.generate_remediation_plan(result.stdout)
        
        # حذف الملف المؤقت بعد الفحص
        if os.path.exists(file_location):
            os.remove(file_location)
            
        return {
            "filename": file.filename, 
            "raw_issues_count": len(json.loads(result.stdout).get("results", [])),
            "ai_analysis": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
