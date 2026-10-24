"""Optional notifications: webhook (Slack/Teams-compatible JSON) and SMTP email."""
import json
import os
import smtplib
from email.message import EmailMessage

import requests


def send(cfg: dict, subject: str, body: str):
    if not cfg:
        return
    if cfg.get("webhook_url_env") and os.environ.get(cfg["webhook_url_env"]):
        try:
            requests.post(os.environ[cfg["webhook_url_env"]], timeout=15,
                          data=json.dumps({"text": f"*{subject}*\n{body}"}),
                          headers={"Content-Type": "application/json"})
        except Exception as e:
            print(f"notify: webhook failed: {e}")
    em = cfg.get("email")
    if em:
        try:
            m = EmailMessage()
            m["Subject"], m["From"], m["To"] = subject, em["from"], ", ".join(em["to"])
            m.set_content(body)
            with smtplib.SMTP(em["host"], em.get("port", 25), timeout=20) as s:
                if em.get("starttls"):
                    s.starttls()
                if em.get("user_env") and os.environ.get(em["user_env"]):
                    s.login(os.environ[em["user_env"]], os.environ[em["pass_env"]])
                s.send_message(m)
        except Exception as e:
            print(f"notify: email failed: {e}")
