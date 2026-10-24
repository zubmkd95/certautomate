"""ClearPass deployment via REST API.

ClearPass imports server certs by *fetching a PKCS#12 from a URL*, so this module
briefly serves the file over HTTP from the machine running certops (one-shot, random
path, random passphrase, torn down immediately after).
Verify the endpoint against your version's API docs at https://<clearpass>/api-docs.
"""
import http.server
import os
import secrets
import threading
from urllib.parse import quote

import requests


class ClearPass:
    def __init__(self, t: dict):
        self.name = t["name"]
        self.base = f"{t.get('scheme', 'https')}://{t['host']}:{t.get('port', 443)}"
        self.client_id = t["client_id"]
        secret = os.environ.get(t["client_secret_env"])
        if not secret:
            raise RuntimeError(f"[{self.name}] env var {t['client_secret_env']} (API client secret) is not set")
        self.secret = secret
        self.verify = t.get("verify_tls", True)
        if self.verify is False:
            requests.packages.urllib3.disable_warnings()
        self.server_name = t["server_name"]            # ClearPass node hostname/name as shown in Admin > Server Manager
        self.services = t.get("services", ["HTTPS(RSA)"])  # e.g. "HTTPS(RSA)", "RADIUS", "HTTPS(ECC)"
        self.serve_host = t["serve_host"]              # IP/hostname of THIS machine, reachable from ClearPass
        self.serve_port = int(t.get("serve_port", 8765))

    def _token(self):
        r = requests.post(self.base + "/api/oauth", timeout=30, verify=self.verify, json={
            "grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.secret})
        if r.status_code != 200:
            raise RuntimeError(f"[{self.name}] OAuth failed: HTTP {r.status_code} {r.text[:200]}")
        return r.json()["access_token"]

    def deploy(self, p12_path, p12_pass, dry_run=False):
        token_path = secrets.token_urlsafe(24)
        url = f"http://{self.serve_host}:{self.serve_port}/{token_path}/bundle.p12"
        if dry_run:
            print(f"  [dry-run] would serve {p12_path} at {url} and PUT to services {self.services}")
            return
        token = self._token()
        data = open(p12_path, "rb").read()
        served = threading.Event()

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self_):
                if self_.path == f"/{token_path}/bundle.p12":
                    self_.send_response(200)
                    self_.send_header("Content-Type", "application/x-pkcs12")
                    self_.send_header("Content-Length", str(len(data)))
                    self_.end_headers()
                    self_.wfile.write(data)
                    served.set()
                else:
                    self_.send_response(404)
                    self_.end_headers()

            def log_message(self_, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("0.0.0.0", self.serve_port), H)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            for svc in self.services:
                path = f"/api/server-cert/name/{quote(self.server_name, safe='')}/{quote(svc, safe='')}"
                r = requests.put(self.base + path, timeout=120, verify=self.verify,
                                 headers={"Authorization": f"Bearer {token}"},
                                 json={"pkcs12_file_url": url, "pkcs12_passphrase": p12_pass})
                if r.status_code >= 400:
                    raise RuntimeError(f"[{self.name}] PUT {path} -> HTTP {r.status_code}: {r.text[:300]}")
                print(f"  ClearPass service '{svc}' updated")
        finally:
            srv.shutdown()
            srv.server_close()
