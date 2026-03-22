#!/usr/bin/python

import smtplib

sender = 'from@fromdomain.com'
receivers = ['info@iabsis.com']

message = """From: From Person <from@fromdomain.com>
To: To Person <info@iabsis.com>
Subject: SMTP e-mail test

This is a test e-mail message.
"""

try:
    smtpObj = smtplib.SMTP('localhost', 8025)
    # smtpObj = smtplib.SMTP('dev-reverse1.iabsis.com', 8025)
    smtpObj.set_debuglevel(1)
    response = smtpObj.sendmail(sender, receivers, message)
    print("Successfully sent email")
    if response:
        print("Rejected recipients:", response)
    smtpObj.quit()
except smtplib.SMTPRecipientsRefused as e:
    print("Recipients refused:")
    for addr, (code, msg) in e.recipients.items():
        print(f"  {addr}: {code} {msg.decode()}")
except smtplib.SMTPException as e:
    print(f"SMTP error: {e}")
except Exception as e:
    print(f"Error: {e}")
