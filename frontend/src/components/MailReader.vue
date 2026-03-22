<template>
  <div v-if="email" class="space-y-4">
    <!-- Email detail -->
    <div class="rounded-xl border border-gray-200 bg-white shadow-sm">
      <div class="border-b border-gray-100 px-6 py-4">
        <h1 class="text-lg font-semibold text-gray-900">{{ email.subject || '(no subject)' }}</h1>
        <p class="mt-1 text-sm text-gray-500">From: <span class="text-gray-700">{{ email.from_address }}</span></p>
        <p class="text-sm text-gray-500">To: <span class="text-gray-700">{{ email.to_addresses }}</span></p>
        <p v-if="email.cc_addresses" class="text-sm text-gray-500">Cc: <span class="text-gray-700">{{ email.cc_addresses }}</span></p>
        <p class="text-xs text-gray-400 mt-1">{{ formatDate(email.received_at) }}</p>
      </div>

      <div class="px-6 py-4">
        <div v-if="email.body_html" class="prose max-w-none">
          <iframe ref="emailFrame" :srcdoc="email.body_html"
                  class="w-full border-0" style="min-height: 300px"
                  sandbox="allow-same-origin"
                  @load="resizeFrame"></iframe>
        </div>
        <pre v-else class="whitespace-pre-wrap text-sm text-gray-700 font-sans">{{ email.body_text }}</pre>
      </div>

      <div v-if="email.attachments && email.attachments.length" class="border-t border-gray-100 px-6 py-4">
        <h3 class="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Attachments</h3>
        <div class="flex flex-wrap gap-2">
          <a v-for="att in email.attachments" :key="att.id" :href="att.url"
             class="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 bg-gray-50 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-100 transition-colors">
            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/>
            </svg>
            {{ att.filename }}
            <span class="text-xs text-gray-400">({{ formatSize(att.size) }})</span>
          </a>
        </div>
      </div>

      <!-- Reply / Forward / Delete -->
      <div class="border-t border-gray-100 px-6 py-4 flex items-center gap-2">
        <button type="button" @click="openReply('reply')"
           class="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
          </svg>
          Reply
        </button>
        <button type="button" @click="openReply('forward')"
           class="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
          </svg>
          Forward
        </button>
        <form method="post" :action="'/mail/' + email.id + '/delete/'" class="ml-auto">
          <input type="hidden" name="csrfmiddlewaretoken" :value="csrfToken">
          <button type="submit" :title="isTrash ? 'Delete permanently' : 'Move to Trash'"
                  :onclick="isTrash ? 'return confirm(\'Permanently delete this email?\')' : ''"
                  class="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50 transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
            Delete
          </button>
        </form>
      </div>
    </div>

    <!-- Inline reply -->
    <div v-if="replyMode" class="space-y-2">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-gray-900">{{ replyMode === 'reply' ? 'Reply' : 'Forward' }}</h3>
        <button type="button" @click="replyMode = null"
                class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>
      <div ref="composeMount" class="rounded-xl border border-gray-200 bg-white shadow-sm"></div>
    </div>
  </div>

  <!-- Placeholder when no email -->
  <div v-else class="flex flex-col items-center justify-center text-gray-400 py-20">
    <svg class="w-12 h-12 mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
            d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
    </svg>
    <p class="text-sm font-medium text-gray-400">Select an email to read</p>
  </div>
</template>

<script>
import { createApp } from 'vue';
import MailCompose from './MailCompose.vue';

export default {
  props: {
    csrfToken: String,
    sendUrl: String,
    signaturesJson: { type: String, default: '[]' },
    defaultSignatureId: { type: [String, Number], default: '' },
    defaultSignatureHtml: { type: String, default: '' },
    initialEmailId: { type: [String, Number], default: '' },
    mailboxName: { type: String, default: '' },
    isTrash: { type: Boolean, default: false },
  },

  data() {
    return {
      email: null,
      replyMode: null,
      composeApp: null,
    };
  },

  mounted() {
    if (this.initialEmailId) {
      this.loadEmail(this.initialEmailId);
    }
    // Listen for email selection from outside
    window.addEventListener('load-email', (e) => {
      this.loadEmail(e.detail.emailId);
    });
  },

  beforeUnmount() {
    this.destroyCompose();
  },

  watch: {
    replyMode(val) {
      if (val) {
        this.$nextTick(() => this.mountCompose());
      } else {
        this.destroyCompose();
      }
    },
  },

  methods: {
    loadEmail(emailId) {
      this.replyMode = null;
      fetch('/api/mail/' + emailId + '/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) return;
          this.email = data;
          // Update URL
          const url = '?mailbox=' + encodeURIComponent(this.mailboxName) + '&email=' + emailId;
          history.replaceState(null, '', url);
          // Update list selection
          document.querySelectorAll('.email-row').forEach(row => {
            row.classList.remove('bg-brand-50', 'border-l-2', 'border-brand-600');
            if (row.dataset.emailId == emailId) {
              row.classList.add('bg-brand-50', 'border-l-2', 'border-brand-600');
              row.classList.remove('bg-blue-50/30');
              row.dataset.isRead = 'true';
              // Update envelope icon
              const icon = row.querySelector('.envelope-icon');
              if (icon) icon.parentElement.innerHTML = '<svg class="w-3.5 h-3.5 text-gray-400 envelope-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 19V8a2 2 0 012-2h14a2 2 0 012 2v11M3 8l9 6 9-6"/></svg>';
              // Update text styles: remove bold/unread styling
              const fromSpan = row.querySelector('a span.truncate');
              if (fromSpan) {
                fromSpan.classList.remove('font-semibold', 'text-gray-900');
                fromSpan.classList.add('font-medium', 'text-gray-600');
              }
              const subjP = row.querySelector('a p');
              if (subjP) {
                subjP.classList.remove('font-medium', 'text-gray-800');
                subjP.classList.add('text-gray-500');
              }
            }
          });
        });
    },

    openReply(mode) {
      this.replyMode = mode;
    },

    mountCompose() {
      this.destroyCompose();
      const el = this.$refs.composeMount;
      if (!el || !this.email) return;

      let prefillTo = '';
      let prefillSubject = '';
      const quote = this.email.body_html || this.email.body_text || '';

      if (this.replyMode === 'reply') {
        prefillTo = this.email.from_address;
        const subj = this.email.subject || '';
        prefillSubject = subj.startsWith('Re:') ? subj : 'Re: ' + subj;
      } else {
        const subj = this.email.subject || '';
        prefillSubject = subj.startsWith('Fwd:') ? subj : 'Fwd: ' + subj;
      }

      this.composeApp = createApp(MailCompose, {
        csrfToken: this.csrfToken,
        sendUrl: this.sendUrl,
        prefillTo,
        prefillSubject,
        prefillQuote: quote,
        signaturesJson: this.signaturesJson,
        defaultSignatureId: this.defaultSignatureId ? String(this.defaultSignatureId) : '',
        defaultSignatureHtml: this.defaultSignatureHtml,
      });
      this.composeApp.mount(el);

      this.$nextTick(() => {
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      });
    },

    destroyCompose() {
      if (this.composeApp) {
        this.composeApp.unmount();
        this.composeApp = null;
      }
    },

    resizeFrame() {
      const frame = this.$refs.emailFrame;
      if (frame) {
        try { frame.style.height = frame.contentDocument.body.scrollHeight + 'px'; } catch(e) {}
      }
    },

    formatDate(iso) {
      return new Date(iso).toLocaleString();
    },

    formatSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
    },
  },
};
</script>
