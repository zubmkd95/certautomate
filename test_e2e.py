"""End-to-end test using real OpenSSL and mock FortiGate/ClearPass HTTP APIs.
Run: python3 tests/test_e2e.py"""
import base64, json, os, subprocess, sys, tempfile, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from certops.cli import main

CALLS = []

class FG(BaseHTTPRequestHandler):
    def _r(self, code=200, body=None):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps(body or {"status": "success"}).encode())
    def _body(self):
        n = int(self.headers.get("Content-Length", 0)); return json.loads(self.rfile.read(n) or b"{}")
    def do_POST(self):
        assert self.headers["Authorization"] == "Bearer tok-fg", "bad token"
        b = self._body(); CALLS.append(("FG", "POST", self.path, b)); self._r()
    def do_PUT(self):
        b = self._body(); CALLS.append(("FG", "PUT", self.path, b)); self._r()
    def do_GET(self):
        self._r(200, {"results": [{"name": "fw1-web-200001010000"}, {"name": "other"}]})
    def do_DELETE(self):
        CALLS.append(("FG", "DELETE", self.path, None)); self._r()
    def log_message(self, *a): pass

class CP(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        self.send_response(200); self.end_headers(); self.wfile.write(json.dumps({"access_token": "cp-tok"}).encode())
    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0)); b = json.loads(self.rfile.read(n))
        data = urllib.request.urlopen(b["pkcs12_file_url"]).read()  # emulate ClearPass fetching it
        p = Path(tempfile.mkdtemp()) / "got.p12"; p.write_bytes(data)
        out = subprocess.run(["openssl", "pkcs12", "-in", str(p), "-passin", f"pass:{b['pkcs12_passphrase']}",
                              "-nokeys", "-clcerts"], capture_output=True, text=True)
        CALLS.append(("CP", "PUT", self.path, "p12_ok" if "BEGIN CERTIFICATE" in out.stdout else "p12_BAD"))
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a): pass

def serve(h, port):
    s = HTTPServer(("127.0.0.1", port), h); threading.Thread(target=s.serve_forever, daemon=True).start(); return s

def main_test():
    serve(FG, 18443); serve(CP, 18444)
    tmp = Path(tempfile.mkdtemp())
    cfg = f"""
renew_before_days: 30
ca: {{dir: {tmp}/pki, default_days: 90}}
targets:
  - {{name: fw1, type: fortigate, scheme: http, host: 127.0.0.1, port: 18443, api_token_env: T_FG,
      services: [admin-gui, ssl-vpn], cert_name_prefix: fw1-web, common_name: fw1.test,
      sans: ["DNS:fw1.test", "IP:127.0.0.1"]}}
  - {{name: cp, type: clearpass, scheme: http, host: 127.0.0.1, port: 18444, client_id: x, client_secret_env: T_CP,
      server_name: cppm1.test, services: ["HTTPS(RSA)", "RADIUS"], serve_host: 127.0.0.1, serve_port: 18765,
      common_name: cppm1.test, sans: ["DNS:cppm1.test"], ekus: [serverAuth, clientAuth]}}
"""
    (tmp / "c.yaml").write_text(cfg)
    os.environ.update(T_FG="tok-fg", T_CP="sec")
    c = ["-c", str(tmp / "c.yaml")]
    assert main(c + ["init-ca", "--cn", "Test CA"]) == 0
    assert main(c + ["issue", "fw1"]) == 0
    assert main(c + ["issue", "cp"]) == 0
    assert main(c + ["renew"]) == 0            # nothing due -> no new calls except live check failing
    n = len(CALLS)
    assert main(c + ["renew", "--force", "--dry-run"]) == 0 and len(CALLS) == n, "dry-run must not call APIs"
    assert main(c + ["status"]) in (0, 1)

    paths = [(c_[1], c_[2]) for c_ in CALLS]
    assert ("POST", "/api/v2/monitor/vpn-certificate/local/import?scope=global") in paths, paths
    assert ("PUT", "/api/v2/cmdb/system/global") in paths
    assert any(p.startswith("/api/v2/cmdb/vpn.ssl/settings") for _, p in paths)
    assert any(m == "DELETE" and "fw1-web-200001010000" in p for m, p in paths), "old cert cleanup"
    assert not any(m == "DELETE" and p.endswith("/other") for m, p in paths), "must not delete unrelated certs"
    assert [c_[3] for c_ in CALLS if c_[0] == "CP"] == ["p12_ok", "p12_ok"], CALLS
    imp = next(c_[3] for c_ in CALLS if c_[0] == "FG" and "local/import" in c_[2])
    pem = base64.b64decode(imp["file_content"]).decode()
    san = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"], input=pem, capture_output=True, text=True).stdout
    assert "fw1.test" in san and "127.0.0.1" in san, san
    print("ALL TESTS PASSED")

if __name__ == "__main__":
    main_test()
