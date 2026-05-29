#!/bin/bash
echo "🚀 Starting AI Security Sentinel on http://127.0.0.1:8000"
# تشغيل FastAPI باستخدام uvicorn
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
