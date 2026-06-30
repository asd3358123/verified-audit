import smtplib


def send(to_addr, subject, body):
    msg = f"To: {to_addr}\r\nSubject: {subject}\r\n\r\n{body}"
    s = smtplib.SMTP("localhost")
    s.sendmail("noreply@example.com", [to_addr], msg)
    return {"sent": True}
