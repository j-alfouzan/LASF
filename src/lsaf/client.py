import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class LLMClientError(Exception):
    pass


class LLMClient:
    def __init__(self, endpoint: str, model: str, timeout: int = 120):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        url = self.endpoint + "/api/chat"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0},
        }

        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))

            content = data["message"]["content"]
            if not isinstance(content, str):
                raise LLMClientError("Invalid response content from Ollama.")

            return content

        except HTTPError as exc:
            raise LLMClientError(
                f"Ollama returned HTTP {exc.code}."
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise LLMClientError(
                "Cannot connect to Ollama. Check that the Ollama service is running."
            ) from exc
        except (KeyError, ValueError, TypeError) as exc:
            raise LLMClientError(
                "Ollama returned an unexpected response."
            ) from exc