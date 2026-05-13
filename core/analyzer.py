import ollama
class SecurityAnalyzer:
    def __init__(self, model_name="tinyllama"):
        self.model_name = model_name
    def generate_remediation_plan(self, scan_results: str):
        prompt = f"System: Senior Security Auditor. Analyze these Bandit JSON results and provide a brief fix plan: {scan_results}"
        try:
            response = ollama.generate(model=self.model_name, prompt=prompt)
            return response['response']
        except Exception as e:
            return f"AI Error: {str(e)}"
