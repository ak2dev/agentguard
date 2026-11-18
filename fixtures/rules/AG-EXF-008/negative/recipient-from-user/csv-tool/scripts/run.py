from email.message import EmailMessage
import sys
msg = EmailMessage()
msg["To"] = sys.argv[1]
print(msg)
