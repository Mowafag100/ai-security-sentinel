import subprocess
import json
import shlex

class SecurityAnalyzer:
    def run_bandit(self, path):
        safe_path = shlex.quote(path)
        cmd = ["bandit", "-r", safe_path, "-f", "json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if not result.stdout: return []
            data = json.loads(result.stdout)
            return data.get('results', [])
        except:
            return []

    def get_ai_remediation(self, issues):
        if not issues: return "Secure."
        summary = str(issues)[:1500].replace("'", "").replace(";", "")
        prompt = f"Analyze and suggest fixes for: {summary}"
        cmd = ["ollama", "run", "tinyllama", prompt]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except:
            return "AI Analysis failed."
