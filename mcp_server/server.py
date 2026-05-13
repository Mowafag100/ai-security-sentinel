import mcp.server.fastmcp as fastmcp
import subprocess
import os

mcp_server = fastmcp.FastMCP("AI-Security-Sentinel")

@mcp_server.tool()
def run_security_scan(path: str):
    """يفحص الكود برمجياً لاكتشاف الثغرات الأمنية باستخدام Bandit."""
    if not os.path.exists(path):
        return "Error: Path not found."
    result = subprocess.run(["bandit", "-r", path, "-f", "json"], capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    mcp_server.run()
