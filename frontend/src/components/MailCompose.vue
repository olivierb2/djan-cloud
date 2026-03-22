<template>
  <!-- To field -->
  <div class="border-b border-gray-100 px-4 py-2 flex items-center gap-2">
    <label class="text-sm font-medium text-gray-500 w-10 flex-shrink-0">To</label>
    <div class="relative flex-1">
      <div class="flex flex-wrap items-center gap-1 min-h-[2rem]">
        <span v-for="(email, i) in toEmails" :key="'to-'+i"
              class="inline-flex items-center gap-1 rounded-full bg-brand-100 px-2 py-0.5 text-xs font-medium text-brand-700">
          {{ email }}
          <button type="button" @click="toEmails.splice(i, 1)" class="ml-0.5 text-brand-500 hover:text-brand-700">&times;</button>
        </span>
        <input ref="toInput" type="text" autocomplete="off" placeholder="Type name or email..."
               class="flex-1 min-w-[200px] border-0 p-0 text-sm outline-none focus:ring-0"
               v-model="toQuery" @keydown="onTagKeydown($event, 'to')" @input="onSearch('to')">
      </div>
      <input type="hidden" name="to" :value="toEmails.join(', ')">
      <div v-if="toSuggestions.length" class="absolute left-0 top-full mt-1 z-50 w-full max-h-48 overflow-y-auto rounded-lg border border-gray-200 bg-white shadow-lg">
        <div v-for="c in toSuggestions" :key="c.email"
             @click="addEmail('to', c.email)"
             class="px-3 py-2 text-sm text-gray-700 hover:bg-gray-100 cursor-pointer">{{ c.label }}</div>
      </div>
    </div>
  </div>

  <!-- Cc field -->
  <div class="border-b border-gray-100 px-4 py-2 flex items-center gap-2">
    <label class="text-sm font-medium text-gray-500 w-10 flex-shrink-0">Cc</label>
    <div class="relative flex-1">
      <div class="flex flex-wrap items-center gap-1 min-h-[2rem]">
        <span v-for="(email, i) in ccEmails" :key="'cc-'+i"
              class="inline-flex items-center gap-1 rounded-full bg-brand-100 px-2 py-0.5 text-xs font-medium text-brand-700">
          {{ email }}
          <button type="button" @click="ccEmails.splice(i, 1)" class="ml-0.5 text-brand-500 hover:text-brand-700">&times;</button>
        </span>
        <input ref="ccInput" type="text" autocomplete="off" placeholder="Add Cc..."
               class="flex-1 min-w-[200px] border-0 p-0 text-sm outline-none focus:ring-0"
               v-model="ccQuery" @keydown="onTagKeydown($event, 'cc')" @input="onSearch('cc')">
      </div>
      <input type="hidden" name="cc" :value="ccEmails.join(', ')">
      <div v-if="ccSuggestions.length" class="absolute left-0 top-full mt-1 z-50 w-full max-h-48 overflow-y-auto rounded-lg border border-gray-200 bg-white shadow-lg">
        <div v-for="c in ccSuggestions" :key="c.email"
             @click="addEmail('cc', c.email)"
             class="px-3 py-2 text-sm text-gray-700 hover:bg-gray-100 cursor-pointer">{{ c.label }}</div>
      </div>
    </div>
  </div>

  <!-- Subject -->
  <div class="border-b border-gray-100 px-4 py-2 flex items-center gap-2">
    <label class="text-sm font-medium text-gray-500 w-10 flex-shrink-0">Subj</label>
    <input type="text" name="subject" v-model="subject" placeholder="Subject"
           class="flex-1 border-0 p-0 text-sm outline-none focus:ring-0">
  </div>

  <!-- Signature selector -->
  <div v-if="signatures.length" class="border-b border-gray-100 px-4 py-2 flex items-center gap-2">
    <label class="text-sm font-medium text-gray-500 flex-shrink-0">Signature</label>
    <select v-model="selectedSignatureId" @change="loadSignature" class="rounded-lg border border-gray-300 px-2 py-1 text-sm">
      <option value="">None</option>
      <option v-for="sig in signatures" :key="sig.id" :value="sig.id">{{ sig.name }}</option>
    </select>
  </div>

  <!-- Toolbar -->
  <div class="border-b border-gray-100 px-4 py-1.5 flex items-center gap-1 flex-wrap">
    <button v-for="btn in toolbarButtons" :key="btn.cmd" type="button" @click="execCmd(btn.cmd)"
            :title="btn.title" class="rounded p-1.5 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
            v-html="btn.icon"></button>
    <div class="w-px h-5 bg-gray-200 mx-1"></div>
    <select @change="execFormatBlock($event)" class="rounded border border-gray-300 px-1 py-0.5 text-xs text-gray-600">
      <option value="p">Paragraph</option>
      <option value="h1">Heading 1</option>
      <option value="h2">Heading 2</option>
      <option value="h3">Heading 3</option>
    </select>
    <select @change="execFontSize($event)" class="rounded border border-gray-300 px-1 py-0.5 text-xs text-gray-600">
      <option value="3">Normal</option>
      <option value="1">Small</option>
      <option value="5">Large</option>
      <option value="7">Huge</option>
    </select>
    <div class="w-px h-5 bg-gray-200 mx-1"></div>
    <input type="color" value="#000000" @input="execColor($event)" title="Text color"
           class="w-6 h-6 rounded border border-gray-300 cursor-pointer p-0">
  </div>

  <!-- Editor -->
  <div ref="editor" contenteditable="true"
       class="px-4 py-4 min-h-[350px] text-sm text-gray-800 outline-none focus:ring-0 prose max-w-none"
       @input="onEditorInput">
  </div>

  <!-- Signature preview -->
  <div v-if="signatureHtml" class="px-4 pb-2">
    <div class="border-t border-gray-100 pt-2 text-sm text-gray-500" v-html="signatureHtml"></div>
  </div>

  <input type="hidden" name="body_html" :value="bodyHtml">

  <!-- Attachments -->
  <div class="border-t border-gray-100 px-4 py-3">
    <div class="flex items-center gap-2 mb-2">
      <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">Attachments</span>
      <label class="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 cursor-pointer transition-colors">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
        </svg>
        From computer
        <input type="file" multiple class="hidden" @change="onLocalFiles">
      </label>
      <button type="button" @click="openPicker"
              class="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
        </svg>
        From Djancloud
      </button>
    </div>
    <div class="flex flex-wrap gap-2">
      <div v-for="(att, i) in attachments" :key="i"
           class="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 bg-gray-50 px-3 py-1.5 text-sm text-gray-700">
        <svg v-if="att.type === 'djancloud'" class="w-3.5 h-3.5 text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
        </svg>
        <svg v-else class="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/>
        </svg>
        {{ att.name }}
        <span class="text-xs text-gray-400">({{ formatSize(att.size) }})</span>
        <button type="button" @click="attachments.splice(i, 1)" class="ml-1 text-gray-400 hover:text-red-500">&times;</button>
      </div>
    </div>
  </div>

  <!-- Actions -->
  <div class="border-t border-gray-100 px-4 py-3 flex items-center justify-between">
    <button type="button" @click="send" :disabled="sending"
            class="inline-flex items-center gap-2 rounded-lg bg-brand-600 px-5 py-2 text-sm font-medium text-white hover:bg-brand-700 transition-colors disabled:opacity-50">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/>
      </svg>
      {{ sending ? 'Sending...' : 'Send' }}
    </button>
    <a href="/mail/" class="text-sm text-gray-500 hover:text-gray-700">Discard</a>
  </div>

  <!-- File Picker Modal -->
  <teleport to="body">
    <div v-if="pickerOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="pickerOpen = false">
      <div class="w-[40rem] rounded-xl bg-white shadow-xl flex flex-col" style="max-height: 80vh" @click.stop>
        <div class="flex items-center justify-between border-b border-gray-200 px-5 py-3">
          <h3 class="text-lg font-semibold text-gray-900">Attach from Djancloud</h3>
          <button type="button" @click="pickerOpen = false" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
        <!-- Breadcrumb -->
        <div class="border-b border-gray-100 px-5 py-2 flex items-center gap-1 text-sm text-gray-500 overflow-x-auto">
          <template v-for="(bc, i) in pickerBreadcrumbs" :key="bc.id">
            <svg v-if="i > 0" class="w-3 h-3 text-gray-300 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
            <button type="button" @click="navigatePicker(bc.id)" class="hover:text-brand-600 whitespace-nowrap">{{ bc.name }}</button>
          </template>
        </div>
        <!-- Items -->
        <div class="flex-1 overflow-y-auto">
          <!-- My Files section -->
          <div v-if="pickerIsRoot">
            <div class="px-4 py-2 bg-gray-50 border-b border-gray-100">
              <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">My files</span>
            </div>
          </div>
          <div class="divide-y divide-gray-100">
            <template v-for="item in pickerItems" :key="item.id">
              <div v-if="item.type === 'folder'" @click="navigatePicker(item.id)"
                   class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer">
                <svg class="w-5 h-5 text-yellow-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                </svg>
                <span class="text-sm text-gray-700">{{ item.name }}</span>
              </div>
              <div v-else @click="togglePickerFile(item)"
                   class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer"
                   :class="{'bg-brand-50 ring-1 ring-brand-200': isPickerSelected(item.id)}">
                <svg class="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
                </svg>
                <span class="text-sm text-gray-700 flex-1">{{ item.name }}</span>
                <span class="text-xs text-gray-400">{{ formatSize(item.size) }}</span>
                <svg v-if="isPickerSelected(item.id)" class="w-4 h-4 text-brand-600" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                </svg>
              </div>
            </template>
          </div>

          <!-- Shared section -->
          <template v-if="pickerShared.length">
            <div class="px-4 py-2 bg-gray-50 border-y border-gray-100">
              <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">Shared</span>
            </div>
            <div class="divide-y divide-gray-100">
              <div v-for="item in pickerShared" :key="'s'+item.id"
                   @click="navigatePicker(item.id)"
                   class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer">
                <svg class="w-5 h-5 text-brand-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">{{ item.name }}</span>
              </div>
            </div>
          </template>

          <!-- Contacts section -->
          <template v-if="pickerContacts.length">
            <div class="px-4 py-2 bg-gray-50 border-y border-gray-100">
              <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">Shared with contact</span>
            </div>
            <div class="divide-y divide-gray-100">
              <div v-for="item in pickerContacts" :key="'c'+item.id"
                   @click="navigatePicker(item.id)"
                   class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer">
                <svg class="w-5 h-5 text-teal-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">{{ item.name }}</span>
              </div>
            </div>
          </template>

          <div v-if="!pickerItems.length && !pickerShared.length && !pickerContacts.length" class="px-4 py-8 text-center text-sm text-gray-400">Empty folder</div>
        </div>
        <div class="border-t border-gray-200 px-5 py-3 flex justify-end gap-2">
          <button type="button" @click="pickerOpen = false"
                  class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
          <button type="button" @click="confirmPicker" :disabled="!pickerSelected.length"
                  class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
            Attach selected
          </button>
        </div>
      </div>
    </div>
  </teleport>
</template>

<script>
export default {
  props: {
    csrfToken: String,
    sendUrl: String,
    prefillTo: { type: String, default: '' },
    prefillSubject: { type: String, default: '' },
    prefillQuote: { type: String, default: '' },
    signaturesJson: { type: String, default: '[]' },
    defaultSignatureId: { type: [String, Number], default: '' },
    defaultSignatureHtml: { type: String, default: '' },
  },

  data() {
    return {
      toEmails: this.prefillTo ? this.prefillTo.split(',').map(e => e.trim()).filter(Boolean) : [],
      ccEmails: [],
      toQuery: '',
      ccQuery: '',
      toSuggestions: [],
      ccSuggestions: [],
      subject: this.prefillSubject,
      selectedSignatureId: this.defaultSignatureId ? String(this.defaultSignatureId) : '',
      signatureHtml: this.defaultSignatureHtml,
      attachments: [],
      sending: false,
      bodyHtml: '',

      // File picker
      pickerOpen: false,
      pickerBreadcrumbs: [],
      pickerItems: [],
      pickerShared: [],
      pickerContacts: [],
      pickerIsRoot: true,
      pickerSelected: [],

      searchTimers: { to: null, cc: null },

      toolbarButtons: [
        { cmd: 'bold', title: 'Bold', icon: '<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24"><path d="M6 4h8a4 4 0 014 4 4 4 0 01-4 4H6z"/><path d="M6 12h9a4 4 0 014 4 4 4 0 01-4 4H6z"/></svg>' },
        { cmd: 'italic', title: 'Italic', icon: '<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="19" y1="4" x2="10" y2="4"/><line x1="14" y1="20" x2="5" y2="20"/><line x1="15" y1="4" x2="9" y2="20"/></svg>' },
        { cmd: 'underline', title: 'Underline', icon: '<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 3v7a6 6 0 006 6 6 6 0 006-6V3"/><line x1="4" y1="21" x2="20" y2="21"/></svg>' },
        { cmd: 'insertUnorderedList', title: 'Bullet list', icon: '<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/></svg>' },
        { cmd: 'insertOrderedList', title: 'Numbered list', icon: '<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="10" y1="6" x2="21" y2="6"/><line x1="10" y1="12" x2="21" y2="12"/><line x1="10" y1="18" x2="21" y2="18"/></svg>' },
        { cmd: 'createLink', title: 'Insert link', icon: '<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>' },
      ],
    };
  },

  mounted() {
    if (this.prefillQuote) {
      this.$refs.editor.innerHTML = '<br><br><blockquote style="border-left:3px solid #ccc;padding-left:12px;margin-left:0;color:#666">' + this.prefillQuote + '</blockquote>';
    }
    // Close suggestions on outside click
    document.addEventListener('click', this.closeSuggestions);
  },

  beforeUnmount() {
    document.removeEventListener('click', this.closeSuggestions);
  },

  computed: {
    signatures() {
      try { return JSON.parse(this.signaturesJson); } catch { return []; }
    },
  },

  methods: {
    closeSuggestions(e) {
      if (!this.$el.contains(e.target)) {
        this.toSuggestions = [];
        this.ccSuggestions = [];
      }
    },

    addEmail(field, email) {
      email = email.trim();
      const list = field === 'to' ? this.toEmails : this.ccEmails;
      if (email && !list.includes(email)) list.push(email);
      if (field === 'to') { this.toQuery = ''; this.toSuggestions = []; }
      else { this.ccQuery = ''; this.ccSuggestions = []; }
    },

    onTagKeydown(e, field) {
      const list = field === 'to' ? this.toEmails : this.ccEmails;
      const query = field === 'to' ? this.toQuery : this.ccQuery;
      if (e.key === 'Enter' || e.key === ',' || e.key === 'Tab') {
        e.preventDefault();
        if (query.trim()) this.addEmail(field, query);
      }
      if (e.key === 'Backspace' && !query && list.length) list.pop();
    },

    onSearch(field) {
      const q = field === 'to' ? this.toQuery : this.ccQuery;
      clearTimeout(this.searchTimers[field]);
      if (q.trim().length < 1) {
        if (field === 'to') this.toSuggestions = [];
        else this.ccSuggestions = [];
        return;
      }
      this.searchTimers[field] = setTimeout(() => {
        fetch(`/api/contacts/search/?q=${encodeURIComponent(q.trim())}`, {
          headers: { 'X-Requested-With': 'XMLHttpRequest' },
        })
          .then(r => r.json())
          .then(data => {
            if (field === 'to') this.toSuggestions = data;
            else this.ccSuggestions = data;
          });
      }, 200);
    },

    execCmd(cmd) {
      this.$refs.editor.focus();
      if (cmd === 'createLink') {
        const url = prompt('Enter URL:');
        if (url) document.execCommand(cmd, false, url);
      } else {
        document.execCommand(cmd, false, null);
      }
    },

    execFormatBlock(e) {
      this.$refs.editor.focus();
      document.execCommand('formatBlock', false, e.target.value);
    },

    execFontSize(e) {
      this.$refs.editor.focus();
      document.execCommand('fontSize', false, e.target.value);
    },

    execColor(e) {
      this.$refs.editor.focus();
      document.execCommand('foreColor', false, e.target.value);
    },

    onEditorInput() {
      // Keep bodyHtml synced
      this.bodyHtml = this.$refs.editor.innerHTML;
    },

    loadSignature() {
      if (!this.selectedSignatureId) { this.signatureHtml = ''; return; }
      fetch(`/mail/settings/signatures/${this.selectedSignatureId}/content/`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then(r => r.json())
        .then(data => { this.signatureHtml = data.html; });
    },

    formatSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
    },

    onLocalFiles(e) {
      for (const f of e.target.files) {
        this.attachments.push({ type: 'local', file: f, name: f.name, size: f.size });
      }
      e.target.value = '';
    },

    // File picker
    openPicker() {
      this.pickerSelected = [];
      this.pickerOpen = true;
      this.navigatePicker(null);
    },

    navigatePicker(folderId) {
      const url = folderId ? `/api/filepicker/${folderId}/` : '/api/filepicker/';
      fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(r => r.json())
        .then(data => {
          this.pickerBreadcrumbs = data.breadcrumbs;
          this.pickerItems = data.items;
          this.pickerShared = data.shared || [];
          this.pickerContacts = data.contacts || [];
          this.pickerIsRoot = !!(data.shared || data.contacts);
        });
    },

    isPickerSelected(id) {
      return this.pickerSelected.some(f => f.id === id);
    },

    togglePickerFile(item) {
      const idx = this.pickerSelected.findIndex(f => f.id === item.id);
      if (idx >= 0) this.pickerSelected.splice(idx, 1);
      else this.pickerSelected.push({ id: item.id, name: item.name, size: item.size });
    },

    confirmPicker() {
      for (const sf of this.pickerSelected) {
        if (!this.attachments.some(a => a.type === 'djancloud' && a.fileId === sf.id)) {
          this.attachments.push({ type: 'djancloud', fileId: sf.id, name: sf.name, size: sf.size });
        }
      }
      this.pickerOpen = false;
    },

    send() {
      // Finalize body HTML
      let html = this.$refs.editor.innerHTML;
      if (this.signatureHtml) html += '<br>' + this.signatureHtml;

      // Flush pending input
      if (this.toQuery.trim()) this.addEmail('to', this.toQuery);
      if (this.ccQuery.trim()) this.addEmail('cc', this.ccQuery);

      const formData = new FormData();
      formData.append('csrfmiddlewaretoken', this.csrfToken);
      formData.append('to', this.toEmails.join(', '));
      formData.append('cc', this.ccEmails.join(', '));
      formData.append('subject', this.subject);
      formData.append('body_html', html);

      // Local files
      this.attachments.filter(a => a.type === 'local' && a.file).forEach(a => {
        formData.append('attachments', a.file);
      });

      // Djancloud IDs
      formData.append('djancloud_file_ids',
        this.attachments.filter(a => a.type === 'djancloud').map(a => a.fileId).join(','));

      this.sending = true;
      fetch(this.sendUrl, {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then(r => r.json())
        .then(data => {
          if (data.ok) window.location.href = '/mail/?mailbox=Sent';
          else { this.sending = false; alert(data.error || 'Failed to send.'); }
        })
        .catch(() => { this.sending = false; alert('Failed to send.'); });
    },
  },
};
</script>
