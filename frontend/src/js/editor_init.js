import { CollaborativeEditor } from './editor.js';
import { getExportFormats, exportMarkdown } from './pandoc-export.js';
import '../css/editor.css';

document.addEventListener('DOMContentLoaded', () => {
  const config = window.editorConfig;
  if (!config) {
    console.error('Editor config not found');
    return;
  }

  const container = document.getElementById('editor');
  if (!container) {
    console.error('Editor container not found');
    return;
  }

  const connectionStatus = document.getElementById('connection-status');
  const usersCount = document.getElementById('users-count');
  const usersNumber = document.getElementById('users-number');
  const saveBtn = document.getElementById('save-btn');

  let hasUnsavedChanges = false;
  let saving = false;
  let autoSaveTimeout = null;

  const editor = new CollaborativeEditor({
    container,
    fileId: config.fileId,
    initialContent: config.initialContent,
    readonly: !config.canWrite,
    userName: config.userName || 'Anonymous',
    onContentChange: (markdown) => {
      hasUnsavedChanges = true;
      if (config.canWrite) {
        clearTimeout(autoSaveTimeout);
        autoSaveTimeout = setTimeout(() => saveContent(markdown), 2000);
      }
    },
    onConnectionStatusChange: (connected) => {
      if (connected) {
        connectionStatus.innerHTML = `
          <span class="w-2 h-2 rounded-full bg-green-500"></span>
          Connected
        `;
      } else {
        connectionStatus.innerHTML = `
          <span class="w-2 h-2 rounded-full bg-red-500"></span>
          Disconnected
        `;
      }
    },
    onUsersChange: (count) => {
      usersNumber.textContent = count;
      if (count > 1) {
        usersCount.classList.remove('hidden');
      } else {
        usersCount.classList.add('hidden');
      }
    },
  });

  async function saveContent(markdown) {
    if (saving || !config.canWrite) return;

    saving = true;
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = `
        <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
        </svg>
        Saving...
      `;
    }

    try {
      const content = markdown || (isRawMode ? rawEditor.value : editor.getMarkdown());
      const response = await fetch(`/api/files/${config.fileId}/save/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken'),
        },
        body: JSON.stringify({ content }),
      });

      if (response.ok) {
        hasUnsavedChanges = false;
        if (saveBtn) {
          saveBtn.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            Saved
          `;
          setTimeout(() => {
            if (saveBtn) {
              saveBtn.innerHTML = `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/>
                </svg>
                Save
              `;
            }
          }, 2000);
        }
      } else {
        throw new Error('Save failed');
      }
    } catch (error) {
      console.error('Error saving:', error);
      if (saveBtn) {
        saveBtn.innerHTML = `
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
          Error
        `;
        setTimeout(() => {
          if (saveBtn) {
            saveBtn.innerHTML = `
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/>
              </svg>
              Save
            `;
          }
        }, 2000);
      }
    } finally {
      saving = false;
      if (saveBtn) {
        saveBtn.disabled = false;
      }
    }
  }

  if (saveBtn) {
    saveBtn.addEventListener('click', () => {
      saveContent();
    });
  }

  // Raw toggle
  const toggleRawBtn = document.getElementById('toggle-raw-btn');
  const rawEditor = document.getElementById('raw-editor');
  let isRawMode = false;

  if (toggleRawBtn && rawEditor) {
    toggleRawBtn.addEventListener('click', () => {
      isRawMode = !isRawMode;
      if (isRawMode) {
        // Switch to raw: copy markdown to textarea
        rawEditor.value = editor.getMarkdown();
        container.classList.add('hidden');
        rawEditor.classList.remove('hidden');
        toggleRawBtn.innerHTML = `
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
          </svg>
          Preview
        `;
      } else {
        // Switch back to WYSIWYG
        const rawContent = rawEditor.value;
        const originalMd = editor.getMarkdown();
        if (rawContent !== originalMd && config.canWrite) {
          // Raw was modified: save then reload to sync the editor
          saveContent(rawContent).then(() => {
            window.location.reload();
          });
          return;
        }
        // No changes: just show the WYSIWYG editor again
        rawEditor.classList.add('hidden');
        container.classList.remove('hidden');
        toggleRawBtn.innerHTML = `
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
          </svg>
          Raw
        `;
      }
    });

    // When typing in raw mode, mark as unsaved
    rawEditor.addEventListener('input', () => {
      hasUnsavedChanges = true;
      if (config.canWrite) {
        clearTimeout(autoSaveTimeout);
        autoSaveTimeout = setTimeout(() => saveContent(rawEditor.value), 2000);
      }
    });
  }

  // Export dropdown
  const exportBtn = document.getElementById('export-btn');
  const exportDropdown = document.getElementById('export-dropdown');
  const exportFormatsContainer = document.getElementById('export-formats');

  if (exportBtn && exportDropdown && exportFormatsContainer) {
    const formats = getExportFormats();
    formats.forEach((format) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors';
      btn.textContent = format.label;
      btn.addEventListener('click', () => handleExport(format.id));
      exportFormatsContainer.appendChild(btn);
    });

    exportBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      exportDropdown.classList.toggle('hidden');
    });

    document.addEventListener('click', () => {
      exportDropdown.classList.add('hidden');
    });

    exportDropdown.addEventListener('click', (e) => {
      e.stopPropagation();
    });
  }

  async function handleExport(formatId) {
    const exportDropdown = document.getElementById('export-dropdown');
    exportDropdown.classList.add('hidden');

    const exportBtn = document.getElementById('export-btn');
    const originalHtml = exportBtn.innerHTML;
    exportBtn.disabled = true;
    exportBtn.innerHTML = `
      <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
      </svg>
      Loading...
    `;

    try {
      const markdown = editor.getMarkdown();
      const baseName = (config.fileName || 'document').replace(/\.[^.]+$/, '');
      await exportMarkdown(markdown, formatId, baseName);
    } catch (err) {
      console.error('Export failed:', err);
      alert('Export failed: ' + err.message);
    } finally {
      exportBtn.disabled = false;
      exportBtn.innerHTML = originalHtml;
    }
  }

  window.addEventListener('beforeunload', (e) => {
    if (hasUnsavedChanges && config.canWrite) {
      e.preventDefault();
      e.returnValue = '';
      return '';
    }
  });
});

function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}
