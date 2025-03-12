import requests
import smtplib
from email.message import EmailMessage
import config

def send_slack_notification(message):
    payload = {"text": message}
    requests.post(config.SLACK_WEBHOOK, json=payload)

def send_email_notification(to_email, message):
    msg = EmailMessage()
    msg.set_content(message)
    msg["Subject"] = "PentestAutomator Alert"
    msg["From"] = config.EMAIL_SENDER
    msg["To"] = to_email

    with smtplib.SMTP_SSL(config.SMTP_SERVER, config.SMTP_PORT) as server:
        server.login(config.EMAIL_SENDER, config.EMAIL_PASSWORD)
        server.send_message(msg)
