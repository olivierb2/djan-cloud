import { createApp } from 'vue';
import MailCompose from '../components/MailCompose.vue';
import '../css/mail_compose.css';

// Expose for inline reply mounting
window.__vue_createApp = createApp;
window.__vue_MailCompose = MailCompose;

const el = document.getElementById('mail-compose-app');
if (el) {
  const app = createApp(MailCompose, {
    csrfToken: el.dataset.csrfToken,
    sendUrl: el.dataset.sendUrl,
    prefillTo: el.dataset.prefillTo || '',
    prefillSubject: el.dataset.prefillSubject || '',
    prefillQuote: el.dataset.prefillQuote || '',
    signaturesJson: el.dataset.signatures || '[]',
    defaultSignatureId: el.dataset.defaultSignatureId || '',
    defaultSignatureHtml: el.dataset.defaultSignatureHtml || '',
  });
  app.mount(el);
}
