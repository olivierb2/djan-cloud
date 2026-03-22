import { createApp } from 'vue';
import MailReader from '../components/MailReader.vue';
import '../css/mail_compose.css';

const el = document.getElementById('mail-reader-app');
if (el) {
  const app = createApp(MailReader, {
    csrfToken: el.dataset.csrfToken,
    sendUrl: el.dataset.sendUrl,
    signaturesJson: el.dataset.signatures || '[]',
    defaultSignatureId: el.dataset.defaultSignatureId || '',
    defaultSignatureHtml: el.dataset.defaultSignatureHtml || '',
    initialEmailId: el.dataset.initialEmailId || '',
    mailboxName: el.dataset.mailboxName || '',
    isTrash: el.dataset.isTrash === 'true',
  });
  app.mount(el);

  // Wire up email link clicks
  document.querySelectorAll('.email-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      window.dispatchEvent(new CustomEvent('load-email', {
        detail: { emailId: link.dataset.emailId }
      }));
    });
  });
}
