"""FortiGate deployment via FortiOS REST API (API token auth)."""
import base64
import os
from datetime import datetime, timezone
from urllib.parse import quote

import requests


class FortiGate:
    def __init__(self, t: dict):
        self.name = t["name"]
        self.base = f"{t.get('scheme', 'https')}://{t['host']}:{t.get('port', 443)}"
        token = os.environ.get(t["api_token_env"])
        if not token:
            raise RuntimeError(f"[{self.name}] env var {t['api_token_env']} (API token) is not set")
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {token}"
        verify = t.get("verify_tls", True)
        self.s.verify = verify  # True, False, or path to CA bundle (e.g. your own CA)
        if verify is False:
            requests.packages.urllib3.disable_warnings()
        self.vdom = t.get("vdom", "root")
        self.services = t.get("services", ["admin-gui"])
        self.prefix = t.get("cert_name_prefix", t["name"])
        self.cleanup = t.get("cleanup_old", True)

    def _call(self, method, path, **kw):
        r = self.s.request(method, self.base + path, timeout=30, **kw)
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code >= 400 or body.get("status") == "error":
            raise RuntimeError(f"[{self.name}] {method} {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return body

    def deploy(self, cert_pem: str, key_pem: str, ca_pem: str, dry_run=False) -> str:
        new_name = f"{self.prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        if dry_run:
            print(f"  [dry-run] import cert '{new_name}', set services {self.services}, cleanup={self.cleanup}")
            return new_name

        # 1. Import CA (ignored if it already exists)
        try:
            self._call("POST", "/api/v2/monitor/vpn-certificate/ca/import",
                       params={"scope": "global"},
                       json={"import_method": "file", "scope": "global", "file_content": b64(ca_pem)})
        except RuntimeError as e:
            print(f"  note: CA import skipped/failed (likely already present): {str(e)[:120]}")

        # 2. Import the new leaf cert + key under a unique, dated name
        self._call("POST", "/api/v2/monitor/vpn-certificate/local/import",
                   params={"scope": "global"},
                   json={"type": "regular", "certname": new_name, "scope": "global",
                         "file_content": b64(cert_pem), "key_file_content": b64(key_pem), "password": ""})
        print(f"  imported certificate as '{new_name}'")

        # 3. Point services at it
        for svc in self.services:
            self._bind(svc, new_name)

        # 4. Remove superseded certs from earlier runs
        if self.cleanup:
            self._cleanup(new_name)
        return new_name

    def _bind(self, svc, name):
        if svc == "admin-gui":
            self._call("PUT", "/api/v2/cmdb/system/global", json={"admin-server-cert": name})
        elif svc == "ssl-vpn":
            self._call("PUT", "/api/v2/cmdb/vpn.ssl/settings", params={"vdom": self.vdom},
                       json={"servercert": name})
        else:
            raise ValueError(f"[{self.name}] unknown service '{svc}' (supported: admin-gui, ssl-vpn)")
        print(f"  bound '{svc}' -> {name}")

    def _cleanup(self, keep):
        data = self._call("GET", "/api/v2/cmdb/vpn.certificate/local", params={"vdom": "root"})
        for item in data.get("results", []):
            n = item.get("name", "")
            if n.startswith(self.prefix + "-") and n != keep:
                try:
                    self._call("DELETE", f"/api/v2/cmdb/vpn.certificate/local/{quote(n, safe='')}")
                    print(f"  removed old certificate '{n}'")
                except RuntimeError as e:
                    print(f"  could not remove '{n}' (probably still in use): {str(e)[:100]}")
