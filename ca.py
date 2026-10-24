"""OpenSSL-backed CA operations: init CA, issue certs, build bundles."""
import json
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


class OpenSSLError(RuntimeError):
    pass


def run_openssl(args, env_extra=None, input_bytes=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    p = subprocess.run(["openssl", *args], capture_output=True, env=env, input=input_bytes)
    if p.returncode != 0:
        raise OpenSSLError(f"openssl {' '.join(args[:2])} failed: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout.decode(errors="replace")


def _keygen(path: Path, key_type: str):
    if key_type == "rsa2048":
        run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(path)])
    elif key_type == "rsa4096":
        run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(path)])
    elif key_type == "ecdsa-p256":
        run_openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(path)])
    elif key_type == "ecdsa-p384":
        run_openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", str(path)])
    else:
        raise ValueError(f"unknown key_type {key_type}")
    os.chmod(path, 0o600)


class CA:
    def __init__(self, cfg: dict):
        self.dir = Path(cfg["dir"]).expanduser()
        self.cert = Path(cfg.get("cert", self.dir / "ca" / "ca.crt")).expanduser()
        self.key = Path(cfg.get("key", self.dir / "ca" / "ca.key")).expanduser()
        # Optional intermediate chain file (PEM) to append to issued chains
        self.chain_extra = Path(cfg["chain_extra"]).expanduser() if cfg.get("chain_extra") else None
        self.key_pass_env = cfg.get("key_pass_env")  # name of env var holding CA key passphrase
        self.default_days = int(cfg.get("default_days", 397))
        self.key_type = cfg.get("leaf_key_type", "rsa2048")
        self.issued_dir = self.dir / "issued"
        self.p12_legacy = bool(cfg.get("p12_legacy", False))

    # ---- CA creation ----
    def init(self, cn: str, days: int = 3650, key_type: str = "rsa4096"):
        if self.cert.exists() or self.key.exists():
            raise FileExistsError(f"CA already exists at {self.cert} - refusing to overwrite")
        self.cert.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cert.parent, 0o700)
        _keygen(self.key, key_type)
        if self.key_pass_env and os.environ.get(self.key_pass_env):
            tmp = self.key.with_suffix(".enc")
            run_openssl(["pkey", "-in", str(self.key), "-aes256", "-out", str(tmp),
                         "-passout", f"env:{self.key_pass_env}"])
            tmp.replace(self.key)
            os.chmod(self.key, 0o600)
        run_openssl(["req", "-new", "-x509", "-key", str(self.key), "-subj", f"/CN={cn}",
                     "-days", str(days), "-sha256",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                     "-addext", "subjectKeyIdentifier=hash",
                     "-out", str(self.cert), *self._passin()])

    def _passin(self):
        return ["-passin", f"env:{self.key_pass_env}"] if self.key_pass_env else []

    # ---- Issuing ----
    def target_dir(self, name: str) -> Path:
        d = self.issued_dir / name
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        return d

    def issue(self, name: str, cn: str, sans: list, days: int = None, ekus=("serverAuth",)) -> dict:
        """Generate key + CSR and sign with the CA. Returns paths. Previous files are archived."""
        if not self.cert.exists() or not self.key.exists():
            raise FileNotFoundError("CA not found. Run `certops init-ca` or point ca.cert/ca.key at your existing CA.")
        days = days or self.default_days
        d = self.target_dir(name)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        # archive previous material
        for fn in ("key.pem", "cert.pem", "fullchain.pem", "bundle.p12"):
            p = d / fn
            if p.exists():
                arch = d / "archive" / stamp
                arch.mkdir(parents=True, exist_ok=True)
                p.replace(arch / fn)

        key, csr, crt = d / "key.pem", d / "req.csr", d / "cert.pem"
        _keygen(key, self.key_type)
        san_str = ",".join(sans) if sans else f"DNS:{cn}"
        run_openssl(["req", "-new", "-key", str(key), "-subj", f"/CN={cn}", "-out", str(csr)])
        ext = (
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            f"extendedKeyUsage={','.join(ekus)}\n"
            f"subjectAltName={san_str}\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
            f.write(ext)
            extf = f.name
        serial = "0x" + secrets.token_hex(16)
        try:
            run_openssl(["x509", "-req", "-in", str(csr), "-CA", str(self.cert), "-CAkey", str(self.key),
                         "-set_serial", serial, "-days", str(days), "-sha256", "-extfile", extf,
                         "-out", str(crt), *self._passin()])
        finally:
            os.unlink(extf)
        csr.unlink(missing_ok=True)

        chain = self.cert.read_text()
        if self.chain_extra:
            chain = self.chain_extra.read_text().rstrip() + "\n" + chain
        full = d / "fullchain.pem"
        full.write_text(crt.read_text().rstrip() + "\n" + chain)
        self._audit(name, cn, sans, serial, days)
        return {"key": key, "cert": crt, "fullchain": full, "chain": chain}

    def verify(self, name: str):
        d = self.issued_dir / name
        args = ["verify", "-CAfile", str(self.cert)]
        if self.chain_extra:
            args += ["-untrusted", str(self.chain_extra)]
        run_openssl([*args, str(d / "cert.pem")])
        # key must match cert
        a = run_openssl(["x509", "-in", str(d / "cert.pem"), "-noout", "-pubkey"])
        b = run_openssl(["pkey", "-in", str(d / "key.pem"), "-pubout"])
        if a.strip() != b.strip():
            raise OpenSSLError("private key does not match certificate")

    def make_p12(self, name: str, password: str) -> Path:
        d = self.issued_dir / name
        out = d / "bundle.p12"
        chain_file = d / "chain_only.pem"
        chain_file.write_text(self.cert.read_text() if not self.chain_extra
                              else self.chain_extra.read_text().rstrip() + "\n" + self.cert.read_text())
        args = ["pkcs12", "-export", "-inkey", str(d / "key.pem"), "-in", str(d / "cert.pem"),
                "-certfile", str(chain_file), "-out", str(out), "-passout", "env:CERTOPS_P12_PASS"]
        if self.p12_legacy:
            args.append("-legacy")
        try:
            run_openssl(args, env_extra={"CERTOPS_P12_PASS": password})
        finally:
            chain_file.unlink(missing_ok=True)
        os.chmod(out, 0o600)
        return out

    def _audit(self, name, cn, sans, serial, days):
        self.dir.mkdir(parents=True, exist_ok=True)
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "target": name, "cn": cn,
               "sans": sans, "serial": serial, "days": days}
        with open(self.dir / "issued.jsonl", "a") as f:
            f.write(json.dumps(rec) + "\n")


def cert_not_after(pem_path) -> datetime:
    out = run_openssl(["x509", "-in", str(pem_path), "-noout", "-enddate"])
    # notAfter=Oct 22 12:00:00 2027 GMT
    s = out.strip().split("=", 1)[1]
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def pem_not_after(pem_text: str) -> datetime:
    out = run_openssl(["x509", "-noout", "-enddate"], input_bytes=pem_text.encode())
    s = out.strip().split("=", 1)[1]
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
