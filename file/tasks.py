import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate, make_msgid

from celery import shared_task
from django.conf import settings

logger = logging.getLogger(__name__)


@shared_task
def send_email_task(from_address, to_addresses, cc_addresses, subject,
                    body_text, body_html, attachments=None):
    """Send an email via SMTP relay in background.

    attachments: list of dicts with keys: filename, content_type, data (base64 encoded)
    """
    import base64

    smtp_host = getattr(settings, 'SMTP_RELAY_HOST', None)
    smtp_port = getattr(settings, 'SMTP_RELAY_PORT', 587)
    smtp_user = getattr(settings, 'SMTP_RELAY_USER', None)
    smtp_pass = getattr(settings, 'SMTP_RELAY_PASSWORD', None)
    smtp_tls = getattr(settings, 'SMTP_RELAY_USE_TLS', True)

    if not smtp_host:
        logger.warning("No SMTP_RELAY_HOST configured, cannot send email")
        return False

    attachments = attachments or []
    has_attachments = len(attachments) > 0

    if has_attachments:
        msg = MIMEMultipart('mixed')
        body_part = MIMEMultipart('alternative')
    else:
        msg = MIMEMultipart('alternative')
        body_part = msg

    msg['From'] = from_address
    msg['To'] = to_addresses
    if cc_addresses:
        msg['Cc'] = cc_addresses
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()

    body_part.attach(MIMEText(body_text, 'plain', 'utf-8'))
    body_part.attach(MIMEText(body_html, 'html', 'utf-8'))

    if has_attachments:
        msg.attach(body_part)

    for att in attachments:
        maintype, subtype = att['content_type'].split('/', 1) if '/' in att['content_type'] else ('application', 'octet-stream')
        part = MIMEBase(maintype, subtype)
        part.set_payload(base64.b64decode(att['data']))
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment', filename=att['filename'])
        msg.attach(part)

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        if smtp_tls:
            server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        all_recipients = [a.strip() for a in to_addresses.split(',')]
        if cc_addresses:
            all_recipients += [a.strip() for a in cc_addresses.split(',')]
        server.sendmail(from_address, all_recipients, msg.as_string())
        server.quit()
        logger.info("Email sent from %s to %s", from_address, to_addresses)
        return True
    except Exception as e:
        logger.error("Failed to send email from %s to %s: %s", from_address, to_addresses, e)
        raise


@shared_task
def send_out_of_office_reply(user_id, sender_email, original_subject):
    """Send an out-of-office auto-reply if conditions are met."""
    from .models import User, OutOfOffice, OutOfOfficeReply

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return

    try:
        ooo = user.out_of_office
    except OutOfOffice.DoesNotExist:
        return

    if not ooo.is_active():
        return

    # Don't reply to noreply, mailer-daemon, etc.
    sender_lower = sender_email.lower()
    skip_prefixes = ['noreply@', 'no-reply@', 'mailer-daemon@', 'postmaster@']
    if any(sender_lower.startswith(p) for p in skip_prefixes):
        return

    # Check if we already replied to this sender
    _, created = OutOfOfficeReply.objects.get_or_create(
        user=user, sender_email=sender_lower)
    if not created:
        return

    from_address = user.email or f'{user.username}@localhost'

    smtp_host = getattr(settings, 'SMTP_RELAY_HOST', None)
    smtp_port = getattr(settings, 'SMTP_RELAY_PORT', 587)
    smtp_user = getattr(settings, 'SMTP_RELAY_USER', None)
    smtp_pass = getattr(settings, 'SMTP_RELAY_PASSWORD', None)
    smtp_tls = getattr(settings, 'SMTP_RELAY_USE_TLS', True)

    if not smtp_host:
        logger.warning("No SMTP_RELAY_HOST configured, cannot send OOO reply")
        return

    msg = MIMEMultipart('alternative')
    msg['From'] = from_address
    msg['To'] = sender_email
    msg['Subject'] = ooo.subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()
    msg['Auto-Submitted'] = 'auto-replied'
    msg['X-Auto-Response-Suppress'] = 'All'

    msg.attach(MIMEText(ooo.body, 'plain', 'utf-8'))

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        if smtp_tls:
            server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(from_address, [sender_email], msg.as_string())
        server.quit()
        logger.info("OOO reply sent from %s to %s", from_address, sender_email)
    except Exception as e:
        logger.error("Failed to send OOO reply from %s to %s: %s", from_address, sender_email, e)
        raise
