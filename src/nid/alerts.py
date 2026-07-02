from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage

import requests

from .explain import local_explanation
from .realtime import DetectionEvent


@dataclass
class AlertDelivery:
    sent: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def send_email_message(subject: str, message: str) -> None:
    recipient = os.getenv("NID_EMAIL_TO")
    host = os.getenv("NID_SMTP_HOST")
    if not recipient or not host:
        raise ValueError("Set NID_EMAIL_TO and NID_SMTP_HOST in .env.")
    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = os.getenv("NID_EMAIL_FROM", "nid-alerts@localhost")
    email["To"] = recipient
    email.set_content(message)
    port = int(os.getenv("NID_SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if os.getenv("NID_SMTP_TLS", "1") == "1":
            smtp.starttls()
        username = os.getenv("NID_SMTP_USERNAME")
        password = os.getenv("NID_SMTP_PASSWORD")
        if username and password:
            smtp.login(username, password)
        smtp.send_message(email)


def send_test_email() -> None:
    send_email_message(
        "NID email integration test",
        "Email alerts are configured correctly for the Network Intrusion Detection project.",
    )


def send_alerts_with_status(event: DetectionEvent) -> AlertDelivery:
    delivery = AlertDelivery()
    if not event.predicted_attack:
        return delivery
    message = local_explanation(event)
    webhook = os.getenv("NID_ALERT_WEBHOOK")
    if webhook:
        try:
            requests.post(webhook, json={"text": message, "event": event.__dict__}, timeout=10).raise_for_status()
            delivery.sent.append("webhook")
        except requests.RequestException as error:
            delivery.errors.append(f"webhook: {error}")

    discord_webhook = os.getenv("NID_DISCORD_WEBHOOK")
    if discord_webhook:
        try:
            requests.post(
                discord_webhook,
                json={"content": message[:1900], "username": "NID Security Alerts"},
                timeout=10,
            ).raise_for_status()
            delivery.sent.append("discord")
        except requests.RequestException as error:
            delivery.errors.append(f"discord: {error}")

    telegram_token = os.getenv("NID_TELEGRAM_BOT_TOKEN")
    telegram_chat = os.getenv("NID_TELEGRAM_CHAT_ID")
    if telegram_token and telegram_chat:
        try:
            requests.post(
                f"https://api.telegram.org/bot{telegram_token}/sendMessage",
                json={"chat_id": telegram_chat, "text": message},
                timeout=10,
            ).raise_for_status()
            delivery.sent.append("telegram")
        except requests.RequestException as error:
            delivery.errors.append(f"telegram: {error}")

    recipient = os.getenv("NID_EMAIL_TO")
    host = os.getenv("NID_SMTP_HOST")
    if recipient and host:
        try:
            send_email_message(f"[{event.severity}] {event.category} network threat", message)
            delivery.sent.append("email")
        except (OSError, smtplib.SMTPException, ValueError) as error:
            delivery.errors.append(f"email: {error}")

    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_from = os.getenv("TWILIO_FROM")
    twilio_to = os.getenv("TWILIO_TO")
    if twilio_sid and twilio_token and twilio_from and twilio_to:
        try:
            from twilio.rest import Client
            Client(twilio_sid, twilio_token).messages.create(body=message, from_=twilio_from, to=twilio_to)
            channel = "whatsapp" if twilio_from.startswith("whatsapp:") or twilio_to.startswith("whatsapp:") else "sms"
            delivery.sent.append(channel)
        except Exception as error:
            delivery.errors.append(f"twilio: {error}")
    return delivery


def send_alerts(event: DetectionEvent) -> list[str]:
    return send_alerts_with_status(event).sent
