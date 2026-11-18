import smtplib
server = smtplib.SMTP('localhost')
for addr in recipients:
    server.sendmail('me@example.invalid', addr, 'hello')
