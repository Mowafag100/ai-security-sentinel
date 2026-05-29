import subprocess
import json
import httpx
import numpy as np
from core.schemas import AuditReportSchema

class SecurityAnalyzer:
    def __init__(self, ollama_url: str = "http://127.0.0.1:11434"):
        self.ollama_url = ollama_url
        self.knowledge_base = [
            {"cwe": "CWE-89", "title": "SQL Injection", "fix": "Use parameterized queries / bind variables instead of string formatting."},
            {"cwe": "CWE-79", "title": "Cross-Site Scripting (XSS)", "fix": "Use proper output encoding and context-aware escaping before rendering data."},
            {"cwe": "CWE-22", "title": "Path Traversal", "fix": "Use os.path.abspath and validate against a strict allowed base directory prefix."},
            {"cwe": "CWE-327", "title": "Weak Cryptography", "fix": "Never use md5 or sha1 for passwords. Upgrade to bcrypt, argon2, or hashlib.sha256 with salts."}
        ]
        self.vectors = np.array([
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0]
        ])

    def run_bandit(self, path):
        cmd = ["bandit", "-r", path, "-f", "json", "-q"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if not result.stdout: return []
            data = json.loads(result.stdout)
            return data.get('results', [])
        except:
            return []

    def _get_rag_context(self, issues_summary: str) -> str:
        try:
            query_vec = np.array([1.0, 0.0, 0.0, 0.0])
            if "sql" in issues_summary.lower() or "execute" in issues_summary.lower():
                query_vec = self.vectors[0]
            elif "path" in issues_summary.lower() or "file" in issues_summary.lower():
                query_vec = self.vectors[2]
            elif "hash" in issues_summary.lower() or "md5" in issues_summary.lower():
                query_vec = self.vectors[3]

            scores = np.dot(self.vectors, query_vec)
            best_match_idx = int(np.argmax(scores))
            match = self.knowledge_base[best_match_idx]
            return f"[OWASP Guide for {match['title']} ({match['cwe']})]: {match['fix']}"
        except:
            return ""

    async def get_ai_remediation_async(self, issues) -> dict:
        """طلب معالجة مهيكلة يتم فحصها والتحقق منها عبر Pydantic قبل الإرجاع"""
        if not issues: 
            return AuditReportSchema(status="secure", vulnerabilities_found=0, issues=[]).dict()

        summary = [{"issue": i.get("issue_text"), "line": i.get("line_number"), "test_id": i.get("test_id")} for i in issues[:3]]
        issues_str = json.dumps(summary)
        rag_context = self._get_rag_context(issues_str)

        # استخراج الهيكل القياسي لـ Pydantic كدليل للنموذج اللغوي
        try:
            if hasattr(AuditReportSchema, "model_json_schema"):
                schema_json = json.dumps(AuditReportSchema.model_json_schema())
            else:
                schema_json = json.dumps(AuditReportSchema.schema())
        except:
            schema_json = "{}"

        prompt = (
            f"You are a security expert. Fix these vulnerabilities based on the provided OWASP context.\n"
            f"Context: {rag_context}\n"
            f"Issues: {issues_str}\n\n"
            f"CRITICAL: You must respond ONLY with a raw JSON object that strictly matches this schema:\n"
            f"{schema_json}"
        )

        async with httpx.AsyncClient(timeout=35.0) as client:
            try:
                response = await client.post(f"{self.ollama_url}/api/chat", json={
                    "model": "tinyllama",
                    "messages": [
                        {"role": "system", "content": "You only output pure validated JSON matching the requested schema. No conversational text, no markdown code blocks."},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False
                })
                
                if response.status_code == 200:
                    raw_result = response.json()
                    assistant_message = raw_result["message"]["content"].strip()
                    
                    # تنظيف علامات الاقتباس في حال أضافها النموذج بالخطأ
                    if assistant_message.startswith("```"):
                        assistant_message = assistant_message.split("```")[1]
                        if assistant_message.startswith("json"):
                            assistant_message = assistant_message[4:]
                    assistant_message = assistant_message.strip()

                    # التحقق الصارم من صحة الهيكل عبر Pydantic
                    if hasattr(AuditReportSchema, "model_validate_json"):
                        validated_report = AuditReportSchema.model_validate_json(assistant_message)
                    else:
                        validated_report = AuditReportSchema.parse_raw(assistant_message)
                    
                    return validated_report.dict()
                
                raise ValueError("Ollama non-200")

            except Exception as e:
                # خطة التراجع المهيكلة (Structured Fallback) بنفس قالب Pydantic تمنع الانهيار تماماً
                print(f"⚠️ [STRUCTURED BACKUP TRIGGERED]: {str(e)}")
                
                # تخمين الثغرة الأساسية لبناء تقرير مخصص متوافق
                detected_cwe = "CWE-89"
                desc = "Potential Vulnerability detected by static analyzer engine."
                rem = "Implement input validation and use secure parameterized APIs."
                
                if "path" in issues_str.lower():
                    detected_cwe = "CWE-22"
                    rem = "Use os.path.abspath and verify root directory prefix restrictions."
                
                return AuditReportSchema(
                    status="success_with_structured_fallback",
                    vulnerabilities_found=len(issues[:3]),
                    issues=[{
                        "cwe_id": i.get("test_id", detected_cwe),
                        "severity": i.get("issue_severity", "HIGH"),
                        "line_number": i.get("line_number", 1),
                        "description": i.get("issue_text", desc),
                        "remediation": rem
                    } for i in issues[:3]]
                ).dict()
