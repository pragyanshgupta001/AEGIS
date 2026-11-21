"""Exercise the real HTTP adapters against a local mock API server."""
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import SAMPLE_ANALYSIS

from modules.evidence_loader import demo_files
from modules.llm_analyzer import AnthropicProvider, LLMError, OpenAICompatibleProvider
from modules.pipeline import run_investigation

STATE = {"status": 200, "received": []}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        STATE["received"].append((self.path, dict(self.headers), body))
        if STATE["status"] != 200:
            self.send_response(STATE["status"])
            self.end_headers()
            self.wfile.write(b'{"error": "nope"}')
            return
        if self.path.endswith("/v1/messages"):
            out = {"content": [{"type": "text", "text": json.dumps(SAMPLE_ANALYSIS)}],
                   "usage": {"input_tokens": 900, "output_tokens": 300}}
        else:
            out = {"choices": [{"message": {"content": json.dumps(SAMPLE_ANALYSIS)}}],
                   "usage": {"prompt_tokens": 1000, "completion_tokens": 350}}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def reset():
    STATE.update(status=200, received=[])


def test_openai_compatible_request_and_parse(server, incident, llm_cfg, settings):
    cfg = replace(llm_cfg, base_url=server + "/v1", api_key="secret-key")
    r = run_investigation(incident, demo_files(), cfg, settings, provider=OpenAICompatibleProvider(cfg))
    path, headers, body = STATE["received"][0]
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer secret-key"
    assert body["model"] == "test-model" and body["response_format"] == {"type": "json_object"}
    assert body["messages"][0]["role"] == "system"
    assert r["llm"]["status"] == "success" and r["llm"]["prompt_tokens"] == 1000
    assert "secret-key" not in json.dumps(r)  # the key is never stored in results


def test_anthropic_request_and_parse(server, incident, llm_cfg, settings):
    cfg = replace(llm_cfg, provider="anthropic", base_url=server, api_key="ak")
    r = run_investigation(incident, demo_files(), cfg, settings, provider=AnthropicProvider(cfg))
    path, headers, body = STATE["received"][0]
    assert path == "/v1/messages" and headers["x-api-key"] == "ak" and "system" in body
    assert r["llm"]["status"] == "success" and r["llm"]["completion_tokens"] == 300


@pytest.mark.parametrize("code,needle", [(401, "credentials"), (404, "not found"), (429, "rate limit"), (500, "HTTP 500")])
def test_http_errors_are_reported(server, llm_cfg, code, needle):
    STATE["status"] = code
    cfg = replace(llm_cfg, base_url=server + "/v1")
    with pytest.raises(LLMError, match=needle):
        OpenAICompatibleProvider(cfg).complete("s", [{"role": "user", "content": "u"}])


def test_unreachable_server_is_reported(llm_cfg):
    cfg = replace(llm_cfg, base_url="http://127.0.0.1:9/v1", timeout_seconds=2)
    with pytest.raises(LLMError, match="Could not reach"):
        OpenAICompatibleProvider(cfg).complete("s", [{"role": "user", "content": "u"}])
