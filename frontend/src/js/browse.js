import { openModal, closeModal, getCsrfToken, renderTree, buildSidebarSections } from './common.js';

// Read Django context
const pageData = JSON.parse(document.getElementById('page-data').textContent);
const currentPath = pageData.currentPath;
const canWrite = pageData.canWrite;

// Rename
function openRenameModal(itemType, itemId, currentName) {
    document.getElementById('rename-input').value = currentName;
    document.getElementById('rename-form').action = '/rename/' + itemType + '/' + itemId + '/';
    openModal('rename-modal');
}
window.openRenameModal = openRenameModal;

// Close "New" dropdown on outside click
var newDropdown = document.getElementById('new-dropdown');
if (newDropdown) {
    document.addEventListener('click', e => {
        if (!newDropdown.contains(e.target)) document.getElementById('new-menu').classList.add('hidden');
    });
}

// Drag & drop (only when user can write)
if (canWrite) {
    let dragCounter = 0;
    const dropzone = document.getElementById('dropzone');
    document.body.addEventListener('dragenter', e => { e.preventDefault(); dragCounter++; dropzone.classList.remove('hidden'); });
    document.body.addEventListener('dragleave', e => { e.preventDefault(); dragCounter--; if (dragCounter === 0) dropzone.classList.add('hidden'); });
    document.body.addEventListener('dragover', e => e.preventDefault());
    dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('border-brand-600', 'bg-brand-100'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('border-brand-600', 'bg-brand-100'));
    dropzone.addEventListener('drop', e => {
        e.preventDefault(); dragCounter = 0; dropzone.classList.add('hidden');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const form = document.createElement('form');
            form.method = 'POST'; form.enctype = 'multipart/form-data'; form.style.display = 'none';
            const csrf = document.querySelector('[name=csrfmiddlewaretoken]').value;
            const ci = document.createElement('input'); ci.type = 'hidden'; ci.name = 'csrfmiddlewaretoken'; ci.value = csrf;
            form.appendChild(ci);
            const fi = document.createElement('input'); fi.type = 'file'; fi.name = 'file'; fi.files = files;
            form.appendChild(fi);
            document.body.appendChild(form); form.submit();
        }
    });
}

// Members modal
let currentSfId = null;
let allUsers = [];

function populateUserSelect() {
    const select = document.getElementById('add-member-select');
    if (select.options.length > 1) return;
    allUsers.forEach(u => {
        const opt = document.createElement('option');
        opt.value = u.id; opt.textContent = u.username;
        select.appendChild(opt);
    });
}

function openMembersModal(sfId, sfName) {
    currentSfId = sfId;
    document.getElementById('members-modal-title').textContent = sfName;
    openModal('members-modal');
    loadMembers();
    if (allUsers.length > 0) {
        populateUserSelect();
    } else {
        fetch('/api/users/').then(r => r.json()).then(data => {
            allUsers = data.users;
            populateUserSelect();
        });
    }
}

function loadMembers() {
    const list = document.getElementById('members-list');
    list.innerHTML = '<div class="text-sm text-gray-400 py-2">Loading...</div>';
    fetch('/api/shared-folders/' + currentSfId + '/members/').then(r => r.json()).then(data => {
        if (data.error) { list.innerHTML = '<div class="text-sm text-red-500">' + data.error + '</div>'; return; }
        list.innerHTML = '';
        data.members.forEach(m => {
            const row = document.createElement('div');
            row.className = 'flex items-center gap-2 py-1.5';
            row.innerHTML =
                '<span class="flex-1 text-sm text-gray-700">' + m.username + '</span>' +
                '<select class="rounded border border-gray-300 text-xs px-1.5 py-1" data-uid="' + m.user_id + '">' +
                '<option value="read"' + (m.permission === 'read' ? ' selected' : '') + '>Read</option>' +
                '<option value="write"' + (m.permission === 'write' ? ' selected' : '') + '>Write</option>' +
                '<option value="admin"' + (m.permission === 'admin' ? ' selected' : '') + '>Admin</option>' +
                '</select>' +
                '<button class="text-gray-400 hover:text-red-600" data-uid="' + m.user_id + '" title="Remove">' +
                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>' +
                '</button>';
            row.querySelector('select').addEventListener('change', function() {
                updateMember(this.dataset.uid, this.value);
            });
            row.querySelector('button').addEventListener('click', function() {
                removeMember(this.dataset.uid);
            });
            list.appendChild(row);
        });
    });
}

function updateMember(userId, permission) {
    fetch('/api/shared-folders/' + currentSfId + '/members/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken()},
        body: JSON.stringify({user_id: parseInt(userId), permission: permission})
    }).then(r => r.json());
}

function removeMember(userId) {
    fetch('/api/shared-folders/' + currentSfId + '/members/' + userId + '/', {
        method: 'DELETE',
        headers: {'X-CSRFToken': getCsrfToken()}
    }).then(r => r.json()).then(() => loadMembers());
}

function addMember() {
    const select = document.getElementById('add-member-select');
    const userId = select.value;
    if (!userId) return;
    fetch('/api/shared-folders/' + currentSfId + '/members/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken()},
        body: JSON.stringify({user_id: parseInt(userId), permission: 'read'})
    }).then(r => r.json()).then(data => {
        if (data.error) { alert(data.error); return; }
        select.value = '';
        loadMembers();
    });
}
window.addMember = addMember;

// Create shared folder
function createSharedFolder() {
    const input = document.getElementById('shared-folder-name');
    const name = input.value.trim();
    if (!name) return;
    fetch('/api/shared-folders/create/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken()},
        body: JSON.stringify({name: name})
    }).then(r => r.json()).then(data => {
        if (data.error) { alert(data.error); return; }
        closeModal('shared-folder-modal');
        input.value = '';
        location.reload();
    });
}
window.createSharedFolder = createSharedFolder;

// Search functionality
const searchInput = document.getElementById('search-input');
const searchResults = document.createElement('div');
searchResults.id = 'search-results';
searchResults.className = 'hidden absolute top-full left-0 mt-2 w-96 max-h-96 overflow-y-auto rounded-lg border border-gray-200 bg-white shadow-xl z-50';
searchInput.parentElement.appendChild(searchResults);

let searchTimeout = null;

searchInput.addEventListener('input', (e) => {
    const query = e.target.value.trim();

    clearTimeout(searchTimeout);

    if (query.length < 2) {
        searchResults.classList.add('hidden');
        return;
    }

    searchTimeout = setTimeout(() => {
        fetch(`/api/search/?q=${encodeURIComponent(query)}`)
            .then(r => r.json())
            .then(data => {
                if (data.results.length === 0) {
                    searchResults.innerHTML = '<div class="p-4 text-sm text-gray-400 text-center">No results found</div>';
                } else {
                    searchResults.innerHTML = data.results.map(item => {
                        const icon = item.type === 'folder'
                            ? '<svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 24 24"><path d="M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z"/></svg>'
                            : item.content_type && item.content_type.includes('image')
                                ? '<svg class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>'
                                : item.name.toLowerCase().endsWith('.md')
                                    ? '<svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>'
                                    : '<svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>';

                        return `
                            <a href="${item.url}" class="flex items-start gap-3 px-4 py-3 border-b border-gray-100 hover:bg-gray-50 transition-colors">
                                ${icon}
                                <div class="flex-1 min-w-0">
                                    <div class="font-medium text-sm text-gray-900 truncate">${item.name}</div>
                                    <div class="text-xs text-gray-500 truncate">${item.path}</div>
                                    <div class="text-xs text-gray-400 mt-0.5">${item.location}</div>
                                </div>
                            </a>
                        `;
                    }).join('');
                }
                searchResults.classList.remove('hidden');
            });
    }, 300);
});

// Close search results when clicking outside
document.addEventListener('click', (e) => {
    if (!searchInput.parentElement.contains(e.target)) {
        searchResults.classList.add('hidden');
    }
});

// Close search results on Escape
searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        searchResults.classList.add('hidden');
        searchInput.blur();
    }
});

// Highlight and scroll to file if hash is present
if (window.location.hash) {
    const fileId = window.location.hash.substring(1); // Remove the #
    const fileRow = document.getElementById(fileId);
    if (fileRow) {
        // Add highlight animation
        fileRow.style.backgroundColor = '#fef3c7'; // yellow-100
        setTimeout(() => {
            fileRow.style.transition = 'background-color 1s ease';
            fileRow.style.backgroundColor = '';
        }, 100);

        // Scroll to element
        setTimeout(() => {
            fileRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 100);
    }
}

// Sidebar folder tree
fetch('/api/tree/').then(r => r.json()).then(data => {
    const treeEl = document.getElementById('folder-tree');
    treeEl.innerHTML = '';
    if (data.tree) renderTree(data.tree, treeEl, currentPath, 0, 'folder', { onShareClick: openMembersModal });

    buildSidebarSections(treeEl, data, currentPath, {
        onShareClick: openMembersModal,
        onAddShared: () => openModal('shared-folder-modal'),
    });
});
