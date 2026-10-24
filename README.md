# certops

Automates certificate issuance (your own OpenSSL CA), deployment and renewal for
**2 FortiGates + 1 ClearPass**. Pure Python + the `openssl` binary. Run it daily; it renews anything inside 30 days of expiry.

## What it does
1. `init-ca` (or use your existing OpenSSL CA via `ca.cert` / `ca.key`).
2. Generates key + CSR, signs it with correct SANs/EKUs, verifies chain and key match.
3. **FortiGate** (REST API token): imports the CA and new cert under a dated name, binds it to `admin-gui` and/or `ssl-vpn`, removes superseded certs with the same prefix.
4. **ClearPass** (REST API client): builds a PKCS#12, briefly serves it over HTTP (random path/passphrase), and tells ClearPass to fetch it for each service (`HTTPS(RSA)`, `RADIUS`, ...).
5. `status` compares local expiry with the live TLS endpoint. `renew` can alert via webhook/email on success or failure. Every issuance is logged to `pki/issued.jsonl`.

## Setup
```
pip install -r requirements.txt
cp config.example.yaml config.yaml        # edit hosts, names, SANs
cp deploy/certops.env.example /etc/certops.env && chmod 600 /etc/certops.env   # tokens/secrets
```
**FortiGate:** System > Administrators > New > REST API Admin. Give it a profile allowing Certificates (system/VPN config) and set *Trusted Hosts* to this machine. Put the token in `FG1_TOKEN` / `FG2_TOKEN`.
**ClearPass:** Administration > API Services > API Clients: create a client with grant type `client_credentials` and an operator profile permitting server certificate changes. Secret goes in `CP_SECRET`.

## Usage
```
python -m certops init-ca --cn "Acme Root CA"     # only if you have no CA yet
python -m certops renew --force --dry-run         # shows exactly what would happen, touches nothing
python -m certops issue fw1                       # issue + deploy one target (--no-deploy to only issue)
python -m certops status
python -m certops renew                           # what cron/systemd runs
```
Schedule: copy `deploy/certops.service` and `.timer` to `/etc/systemd/system/`, then `systemctl enable --now certops.timer`.

## Read before production
- **The ClearPass call was NOT tested against a real ClearPass.** It follows the documented `server-cert` API (`PUT /api/server-cert/name/{server}/{service}` with `pkcs12_file_url` + `pkcs12_passphrase`), but check your version's Swagger at `https://<clearpass>/api-docs`. Try it first on a lab node or off-hours; replacing HTTPS restarts web services. In a cluster, run it per node (add one target per node). If it fails, `python -m certops issue cp --no-deploy` leaves key/cert in `pki/issued/cp/` for a manual GUI import.
- **FortiGate payloads** follow the FortiOS 7.x REST API (`vpn-certificate/local/import`, `system/global admin-server-cert`, `vpn.ssl/settings servercert`). Tested only against a mock. Run on `fw1` first. Field names can differ on older FortiOS.
- **Key location:** private keys are generated on this host and pushed to the devices. That's simple but means this host must be locked down (`pki/` is chmod 700; use a passphrase on the CA key, as shown in the example config).
- **Trust:** devices/clients must trust your CA, so import `pki/ca/ca.crt`. Changing the CA later breaks RADIUS/EAP supplicants. Keep the same CA.
- **Firewall:** ClearPass must reach `serve_host:serve_port` (HTTP) on this machine.
- If ClearPass rejects the .p12 (OpenSSL 3 uses modern ciphers), set `p12_legacy: true`.
- Not covered: FortiGate HA secondary sync (the primary syncs certs), FortiGate `ssl-inspection` or IPsec cert bindings, CRL/OCSP.

## Tests
`python3 tests/test_e2e.py` runs the full flow with real OpenSSL against mock FortiGate/ClearPass APIs.
