import asyncio
import email
import email.policy
import logging

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer

from django.core.management.base import BaseCommand

logger = logging.getLogger('smtpserver')


class DjancloudSMTPHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        from file.models import AllowedDomain

        # Extract bare email
        bare = address
        if '<' in bare and '>' in bare:
            bare = bare.split('<')[1].split('>')[0]
        bare = bare.lower().strip()

        # Check domain against allowed domains
        allowed_domains = [d.domain async for d in AllowedDomain.objects.all()]
        if allowed_domains:
            domain = bare.split('@')[-1] if '@' in bare else ''
            if domain not in allowed_domains:
                return f'550 5.1.1 Recipient domain {domain} not allowed'

        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        from file.models import User, Mailbox, Email, EmailAttachment

        raw = envelope.content
        if isinstance(raw, bytes):
            raw_str = raw.decode('utf-8', errors='replace')
        else:
            raw_str = raw

        msg = email.message_from_string(raw_str, policy=email.policy.default)

        from_addr = msg.get('From', envelope.mail_from or '')
        to_addrs = msg.get('To', '')
        cc_addrs = msg.get('Cc', '')
        subject = msg.get('Subject', '')
        message_id = msg.get('Message-ID', '')

        # Extract body
        body_text = ''
        body_html = ''
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                cd = str(part.get('Content-Disposition', ''))
                if 'attachment' in cd:
                    data = part.get_payload(decode=True) or b''
                    attachments.append({
                        'filename': part.get_filename() or 'attachment',
                        'content_type': ct,
                        'data': data,
                        'size': len(data),
                    })
                elif ct == 'text/plain' and not body_text:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode('utf-8', errors='replace')
                elif ct == 'text/html' and not body_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode('utf-8', errors='replace')
        else:
            ct = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode('utf-8', errors='replace')
                if ct == 'text/html':
                    body_html = decoded
                else:
                    body_text = decoded

        # Find matching users by recipient email
        recipients = [addr.strip() for addr in (envelope.rcpt_tos or [])]
        delivered = 0

        from file.models import SharedMailbox

        for rcpt in recipients:
            # Extract bare email from "Name <email>" format
            bare = rcpt
            if '<' in bare and '>' in bare:
                bare = bare.split('<')[1].split('>')[0]
            bare = bare.lower().strip()

            # Try personal user mailbox first
            try:
                user = await User.objects.aget(email__iexact=bare)
            except User.DoesNotExist:
                user = None

            if user:
                mailbox, _ = await Mailbox.objects.aget_or_create(
                    owner=user, name='INBOX', defaults={'system': True})

                mail = await Email.objects.acreate(
                    mailbox=mailbox,
                    message_id=message_id,
                    from_address=from_addr,
                    to_addresses=to_addrs,
                    cc_addresses=cc_addrs,
                    subject=subject,
                    body_text=body_text,
                    body_html=body_html,
                    raw_data=raw_str,
                )

                for att in attachments:
                    await EmailAttachment.objects.acreate(
                        email=mail,
                        filename=att['filename'],
                        content_type=att['content_type'],
                        data=att['data'],
                        size=att['size'],
                    )

                delivered += 1
                logger.info("Delivered email to %s (user: %s)", bare, user.username)
                continue

            # Try shared mailbox alias
            try:
                shared_mb = await SharedMailbox.objects.aget(email_alias__iexact=bare)
            except SharedMailbox.DoesNotExist:
                logger.info("No user or shared mailbox found for recipient: %s", bare)
                continue

            # Deliver to shared mailbox INBOX
            mailbox, _ = await Mailbox.objects.aget_or_create(
                shared_mailbox=shared_mb, owner=None, name='INBOX',
                defaults={'system': True})

            mail = await Email.objects.acreate(
                mailbox=mailbox,
                message_id=message_id,
                from_address=from_addr,
                to_addresses=to_addrs,
                cc_addresses=cc_addrs,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                raw_data=raw_str,
            )

            for att in attachments:
                await EmailAttachment.objects.acreate(
                    email=mail,
                    filename=att['filename'],
                    content_type=att['content_type'],
                    data=att['data'],
                    size=att['size'],
                )

            delivered += 1
            logger.info("Delivered email to shared mailbox %s (%s)", bare, shared_mb.name)

        if delivered == 0:
            logger.warning("No local recipients matched for: %s", recipients)
            return '550 5.1.1 No valid recipients'

        return '250 Message accepted for delivery'


class Command(BaseCommand):
    help = 'Run an SMTP server that stores incoming emails in the database'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
        parser.add_argument('--port', type=int, default=8025, help='Port to listen on')

    def handle(self, *args, **options):
        host = options['host']
        port = options['port']

        handler = DjancloudSMTPHandler()
        controller = Controller(
            handler,
            hostname=host,
            port=port,
            server_hostname='djancloud',
        )

        self.stdout.write(self.style.SUCCESS(
            f'Starting SMTP server on {host}:{port}'
        ))

        controller.start()
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            controller.stop()
            self.stdout.write('SMTP server stopped.')
