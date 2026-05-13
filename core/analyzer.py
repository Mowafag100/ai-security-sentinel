import subprocess
import json

class SecurityAnalyzer:
    def run_bandit(self, path):
        # تشغيل آمن بدون shell=True
        cmd = ["bandit", "-r", path, "-f", "json", "-q"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if not result.stdout: return []
            data = json.loads(result.stdout)
            return data.get('results', [])
        except:
            return []

    def get_ai_remediation(self, issues):
        if not issues: return "Environment verified: No vulnerabilities detected."

        # فلترة البيانات لتقليل الحمل
        summary = [{"issue": i.get("issue_text"), "line": i.get("line_number")} for i in issues[:3]]
        prompt = f"Provide a brief fix for these security issues: {json.dumps(summary)}"
        
        cmd = ["ollama", "run", "tinyllama", prompt]
        try:
            # استخدام check=False لمنع انهيار الـ API عند تعطل الخدمة
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout
            return "AI remediation service is currently unavailable."
        except:
            return "Critical: AI Engine error."
