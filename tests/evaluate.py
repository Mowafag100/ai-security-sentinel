import json
import asyncio
import httpx

# مخرجات حقيقية متوقعة من ماسح Bandit لملف vulnerable_app.py
BANDIT_GROUND_TRUTH = {"B403", "B301", "B608"}

async def run_pipeline_evaluation():
    print("🎯 [STARTING EVALUATION PIPELINE]...")
    # تعديل المسار ليكون اسم الملف مباشرة لأن السيرفر يوجهه تلقائياً لـ allowed_targets
    payload = {"path": "vulnerable_app.py"}
    
    async with httpx.AsyncClient(timeout=40.0) as client:
        try:
            response = await client.post("http://127.0.0.1:8000/analyze", json=payload)
            
            if response.status_code != 200:
                print(f"❌ Failed to connect to server, Status: {response.status_code}")
                try:
                    print(f"Response Detail: {response.json()}")
                except:
                    pass
                return
            
            data = response.json()
            ai_analysis = data.get("ai_analysis", {})
            
            # معالجة ذكية لاستخراج الـ CWEs سواء كانت راجعة كـ Dict أو مستخرجة من الـ Static Fallback
            ai_issues = ai_analysis.get("issues", []) if isinstance(ai_analysis, dict) else []
            
            ai_detected_cwes = set()
            for issue in ai_issues:
                cwe = issue.get("cwe_id", "")
                if cwe:
                    ai_detected_cwes.add(cwe)
            
            print(f"\n🔍 [Ground Truth] Bandit Detected IDs: {BANDIT_GROUND_TRUTH}")
            print(f"🤖 [AI Sentinel] Structured Verified IDs: {ai_detected_cwes}\n")
            
            true_positives = len(BANDIT_GROUND_TRUTH.intersection(ai_detected_cwes))
            false_positives = len(ai_detected_cwes - BANDIT_GROUND_TRUTH)
            false_negatives = len(BANDIT_GROUND_TRUTH - ai_detected_cwes)
            
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            
            print("="*50)
            print("📊 AI EVALUATION PIPELINE METRICS REPORT")
            print("="*50)
            print(f"📈 Precision (الدقة الموجهة): {precision * 100:.1f}%")
            print(f"📉 Recall    (نسبة الاستدعاء): {recall * 100:.1f}%")
            print(f"💯 F1-Score  (التوازن العام): {f1_score * 100:.1f}%")
            print("="*50)
            print("✅ Evaluation complete. System verification logged.")
            
        except Exception as e:
            print(f"❌ Error during evaluation run: {str(e)}")

if __name__ == "__main__":
    asyncio.run(run_pipeline_evaluation())
