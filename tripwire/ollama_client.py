import os
import json
import urllib.request
import urllib.error

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3:latest")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "60"))

class OllamaError(Exception):
    pass

class OllamaClient:
    def __init__(self, base_url: str = OLLAMA_BASE_URL, model: str = OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def check_health(self) -> dict:
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                models = [m.get("name") for m in data.get("models", [])]
                model_exists = self.model in models or any(m.startswith(self.model) for m in models)
                return {"available": True, "model_exists": model_exists}
        except Exception:
            return {"available": False, "model_exists": False}
            
    def generate_json(self, prompt: str) -> dict:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
                result = json.loads(resp.read())
                response_text = result.get("response", "")
                return json.loads(response_text)
        except urllib.error.URLError as e:
            raise OllamaError(f"Connection to Ollama failed: {e}")
        except json.JSONDecodeError as e:
            raise OllamaError(f"Ollama returned malformed JSON: {e}")
