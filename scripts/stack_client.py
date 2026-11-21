"""Shared access to the local stack for scripts (R-07, R-02).

OpenSearch is reached over mTLS with the admin client certificate and the password from
.runtime/ (make deploy); MISP is verified against the same root CA. Secrets are read from
.runtime/ only and never printed.
"""
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CA = ROOT / "certs/root-ca.pem"


def env_file(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def settings():
    s = env_file(ROOT / "config/stack.env")
    if (ROOT / ".env").exists():
        s.update(env_file(ROOT / ".env"))
    return s


def runtime(name, hint):
    path = ROOT / ".runtime" / name
    if not path.exists():
        sys.exit(f"No decrypted secret in .runtime/{name}: run {hint} first.")
    return env_file(path)


class OpenSearch:
    def __init__(self):
        password = runtime(".env.secrets", "make deploy")["OPENSEARCH_ADMIN_PASSWORD"]
        self.ctx = ssl.create_default_context(cafile=str(CA))
        self.ctx.load_cert_chain(ROOT / "certs/admin.pem", ROOT / "certs/admin-key.pem")
        self.base = f"https://localhost:{settings()['OPENSEARCH_PORT']}"
        self.auth = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()

    def call(self, method, path, body=None, ndjson=False):
        data = None
        if body is not None:
            data = body.encode() if ndjson else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": self.auth,
            "Content-Type": "application/x-ndjson" if ndjson else "application/json",
        })
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as err:
            if method == "DELETE" and err.code == 404:
                return {}
            sys.exit(f"{method} {path}: HTTP {err.code} {err.read().decode()[:300]}")

    def reload_index(self, index, template_name, template_file, docs):
        """Apply an index template, recreate the index and bulk-load docs; return the count."""
        self.call("PUT", f"/_index_template/{template_name}", json.loads(Path(template_file).read_text()))
        self.call("DELETE", f"/{index}")
        lines = []
        for doc in docs:
            lines += [json.dumps({"index": {"_index": index}}), json.dumps(doc)]
        result = self.call("POST", "/_bulk?refresh=true", "\n".join(lines) + "\n", ndjson=True)
        if result.get("errors"):
            sys.exit("bulk load failed: " + json.dumps(result)[:500])
        return self.call("GET", f"/{index}/_count")["count"]
