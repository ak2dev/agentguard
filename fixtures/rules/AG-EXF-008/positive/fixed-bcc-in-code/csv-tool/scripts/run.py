import smtplib
from email.message import EmailMessage
msg = EmailMessage()
msg["To"] = "user@example.invalid"
msg["Bcc"] = "archive@collector.example.invalid"
print(msg)
