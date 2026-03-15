import '../css/mail_compose.css';

document.addEventListener('DOMContentLoaded', function () {
  const editor = document.getElementById('editor');
  if (!editor) return;

  // ── WYSIWYG Toolbar ──
  document.querySelectorAll('.toolbar-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      editor.focus();
      const cmd = btn.dataset.cmd;
      if (cmd === 'createLink') {
        const url = prompt('Enter URL:');
        if (url) document.execCommand(cmd, false, url);
      } else {
        document.execCommand(cmd, false, null);
      }
    });
  });

  const formatBlock = document.getElementById('format-block');
  if (formatBlock) {
    formatBlock.addEventListener('change', () => {
      editor.focus();
      document.execCommand('formatBlock', false, formatBlock.value);
    });
  }

  const fontSize = document.getElementById('font-size');
  if (fontSize) {
    fontSize.addEventListener('change', () => {
      editor.focus();
      document.execCommand('fontSize', false, fontSize.value);
    });
  }

  const textColor = document.getElementById('text-color');
  if (textColor) {
    textColor.addEventListener('input', () => {
      editor.focus();
      document.execCommand('foreColor', false, textColor.value);
    });
  }

  // ── Placeholder ──
  function updatePlaceholder() {
    if (
      editor.textContent.trim() === '' &&
      !editor.querySelector('img, blockquote')
    ) {
      editor.classList.add('is-empty');
    } else {
      editor.classList.remove('is-empty');
    }
  }
  editor.addEventListener('input', updatePlaceholder);
  updatePlaceholder();

  // ── Contact autocomplete ──
  function setupAutocomplete(inputId, suggestionsId, hiddenId, tagsId) {
    const input = document.getElementById(inputId);
    const suggestions = document.getElementById(suggestionsId);
    const hidden = document.getElementById(hiddenId);
    const tagsContainer = document.getElementById(tagsId);
    if (!input || !suggestions || !hidden) return;

    let emails = hidden.value
      ? hidden.value
          .split(',')
          .map((e) => e.trim())
          .filter(Boolean)
      : [];
    let debounceTimer = null;

    function renderTags() {
      // Remove existing tags
      tagsContainer
        .querySelectorAll('.email-tag')
        .forEach((t) => t.remove());
      emails.forEach((email, i) => {
        const tag = document.createElement('span');
        tag.className =
          'email-tag inline-flex items-center gap-1 rounded-full bg-brand-100 px-2 py-0.5 text-xs font-medium text-brand-700';
        tag.innerHTML = `${email}<button type="button" data-idx="${i}" class="ml-0.5 text-brand-500 hover:text-brand-700">&times;</button>`;
        tagsContainer.insertBefore(tag, input);
      });
      hidden.value = emails.join(', ');
    }

    function addEmail(email) {
      email = email.trim();
      if (email && !emails.includes(email)) {
        emails.push(email);
        renderTags();
      }
      input.value = '';
      suggestions.classList.add('hidden');
    }

    tagsContainer.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-idx]');
      if (btn) {
        const idx = parseInt(btn.dataset.idx);
        emails.splice(idx, 1);
        renderTags();
      }
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ',' || e.key === 'Tab') {
        e.preventDefault();
        if (input.value.trim()) {
          addEmail(input.value);
        }
      }
      if (
        e.key === 'Backspace' &&
        !input.value &&
        emails.length > 0
      ) {
        emails.pop();
        renderTags();
      }
    });

    input.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      const q = input.value.trim();
      if (q.length < 1) {
        suggestions.classList.add('hidden');
        return;
      }
      debounceTimer = setTimeout(() => {
        fetch(`/api/contacts/search/?q=${encodeURIComponent(q)}`, {
          headers: { 'X-Requested-With': 'XMLHttpRequest' },
        })
          .then((r) => r.json())
          .then((data) => {
            if (data.length === 0) {
              suggestions.classList.add('hidden');
              return;
            }
            suggestions.innerHTML = data
              .map(
                (c) =>
                  `<div class="suggestion-item px-3 py-2 text-sm text-gray-700 hover:bg-gray-100 cursor-pointer" data-email="${c.email}">${c.label}</div>`,
              )
              .join('');
            suggestions.classList.remove('hidden');
          });
      }, 200);
    });

    suggestions.addEventListener('click', (e) => {
      const item = e.target.closest('.suggestion-item');
      if (item) {
        addEmail(item.dataset.email);
      }
    });

    document.addEventListener('click', (e) => {
      if (!suggestions.contains(e.target) && e.target !== input) {
        suggestions.classList.add('hidden');
      }
    });

    // Render initial tags
    if (emails.length > 0) renderTags();
  }

  setupAutocomplete(
    'to-input',
    'to-suggestions',
    'to-hidden',
    'to-tags',
  );
  setupAutocomplete(
    'cc-input',
    'cc-suggestions',
    'cc-hidden',
    'cc-tags',
  );

  // ── Signature loading ──
  const sigSelect = document.getElementById('signature-select');
  const sigPreview = document.getElementById('signature-preview');

  if (sigSelect) {
    sigSelect.addEventListener('change', () => {
      const sigId = sigSelect.value;
      if (!sigId) {
        sigPreview.innerHTML = '';
        return;
      }
      fetch(`/mail/signatures/${sigId}/content/`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then((r) => r.json())
        .then((data) => {
          sigPreview.innerHTML = `<div class="border-t border-gray-100 pt-2 text-sm text-gray-500">${data.html}</div>`;
        });
    });
  }

  // ── Form submission ──
  const form = document.getElementById('compose-form');
  form.addEventListener('submit', function (e) {
    // Collect editor HTML + signature into hidden field
    let html = editor.innerHTML;
    if (sigPreview && sigPreview.innerHTML.trim()) {
      html += '<br>' + sigPreview.innerHTML;
    }
    document.getElementById('body-html-hidden').value = html;

    // Ensure to field has current input value
    const toInput = document.getElementById('to-input');
    const toHidden = document.getElementById('to-hidden');
    if (toInput.value.trim()) {
      const current = toHidden.value
        ? toHidden.value + ', '
        : '';
      toHidden.value = current + toInput.value.trim();
    }

    const ccInput = document.getElementById('cc-input');
    const ccHidden = document.getElementById('cc-hidden');
    if (ccInput && ccInput.value.trim()) {
      const current = ccHidden.value
        ? ccHidden.value + ', '
        : '';
      ccHidden.value = current + ccInput.value.trim();
    }
  });
});
