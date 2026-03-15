import '../css/main.css';

// CSRF helper
export function getCsrfToken() {
    const el = document.querySelector('[name=csrfmiddlewaretoken]');
    return el ? el.value : '';
}

// Modal helpers
export function openModal(id) {
    const m = document.getElementById(id);
    m.classList.remove('hidden');
    m.classList.add('flex');
    var newMenu = document.getElementById('new-menu');
    if (newMenu) newMenu.classList.add('hidden');
    const input = m.querySelector('input[type="text"]');
    if (input) { input.focus(); input.select(); }
}

export function closeModal(id) {
    const m = document.getElementById(id);
    m.classList.add('hidden');
    m.classList.remove('flex');
}

// Global modal close handlers
document.querySelectorAll('[id$="-modal"]').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) closeModal(m.id); });
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelectorAll('[id$="-modal"].flex').forEach(m => closeModal(m.id));
});

// Sidebar folder tree (shared between browse and users)
// options.onShareClick(sfId, name) - callback for share button clicks
export function renderTree(node, container, currentPath, depth, iconType, options) {
    options = options || {};
    const isActive = node.url_path === currentPath;
    const hasChildren = node.children && node.children.length > 0;
    const isOnPath = currentPath === node.url_path || currentPath.startsWith(node.url_path ? node.url_path + '/' : '');

    const item = document.createElement('div');
    item.className = 'tree-item' + (isOnPath && hasChildren ? ' open' : '');

    const row = document.createElement('a');
    row.href = node.url_path ? '/browse/' + node.url_path : '/browse/';
    row.className = 'flex items-center gap-1 px-2 py-1 rounded-md cursor-pointer text-sm select-none no-underline ' +
        (isActive ? 'bg-brand-50 text-brand-700 font-medium' : 'text-gray-700 hover:bg-gray-100');
    row.style.paddingLeft = (depth * 12 + 8) + 'px';

    if (hasChildren) {
        const toggle = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        toggle.setAttribute('class', 'w-3 h-3 text-gray-400 tree-toggle flex-shrink-0');
        toggle.setAttribute('fill', 'none'); toggle.setAttribute('stroke', 'currentColor'); toggle.setAttribute('viewBox', '0 0 24 24');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('stroke-linecap', 'round'); path.setAttribute('stroke-linejoin', 'round'); path.setAttribute('stroke-width', '2'); path.setAttribute('d', 'M9 5l7 7-7 7');
        toggle.appendChild(path);
        toggle.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); item.classList.toggle('open'); });
        row.appendChild(toggle);
    } else {
        const spacer = document.createElement('span'); spacer.className = 'w-3 flex-shrink-0'; row.appendChild(spacer);
    }

    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    if (iconType === 'shared') {
        icon.setAttribute('class', 'w-4 h-4 text-brand-500 flex-shrink-0');
        icon.setAttribute('fill', 'none'); icon.setAttribute('stroke', 'currentColor'); icon.setAttribute('viewBox', '0 0 24 24');
        const ipath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        ipath.setAttribute('stroke-linecap', 'round'); ipath.setAttribute('stroke-linejoin', 'round'); ipath.setAttribute('stroke-width', '2');
        ipath.setAttribute('d', 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z');
        icon.appendChild(ipath);
    } else {
        icon.setAttribute('class', 'w-4 h-4 text-yellow-400 flex-shrink-0');
        icon.setAttribute('fill', 'currentColor'); icon.setAttribute('viewBox', '0 0 24 24');
        const ipath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        ipath.setAttribute('d', 'M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z');
        icon.appendChild(ipath);
    }
    row.appendChild(icon);

    const label = document.createElement('span');
    label.className = 'truncate flex-1'; label.textContent = node.name;
    row.appendChild(label);

    // Share button on root shared folders
    if (iconType === 'shared' && depth === 0 && node.sf_id && options.onShareClick) {
        const shareBtn = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        shareBtn.setAttribute('class', 'w-3.5 h-3.5 text-gray-400 hover:text-brand-600 flex-shrink-0 cursor-pointer');
        shareBtn.setAttribute('fill', 'none'); shareBtn.setAttribute('stroke', 'currentColor'); shareBtn.setAttribute('viewBox', '0 0 24 24');
        const sp = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        sp.setAttribute('stroke-linecap', 'round'); sp.setAttribute('stroke-linejoin', 'round'); sp.setAttribute('stroke-width', '2');
        sp.setAttribute('d', 'M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z');
        shareBtn.appendChild(sp);
        shareBtn.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); options.onShareClick(node.sf_id, node.name); });
        row.appendChild(shareBtn);
    }

    item.appendChild(row);

    if (hasChildren) {
        const childContainer = document.createElement('div'); childContainer.className = 'tree-children';
        node.children.forEach(c => renderTree(c, childContainer, currentPath, depth + 1, 'folder', options));
        item.appendChild(childContainer);
    }
    container.appendChild(item);
}

// Build sidebar sections (shared folders + config) - reused across pages
export function buildSidebarSections(treeEl, data, currentPath, options) {
    options = options || {};
    if (data.is_admin || (data.shared && data.shared.length > 0)) {
        const headingRow = document.createElement('div');
        headingRow.className = 'mt-4 mb-2 px-2 flex items-center justify-between';
        const heading = document.createElement('h2');
        heading.className = 'text-xs font-semibold uppercase tracking-wider text-gray-400';
        heading.textContent = 'Shared';
        headingRow.appendChild(heading);
        if (data.is_admin && options.onAddShared) {
            const addBtn = document.createElement('button');
            addBtn.className = 'w-5 h-5 flex items-center justify-center rounded text-gray-400 hover:text-brand-600 hover:bg-gray-100';
            addBtn.innerHTML = '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>';
            addBtn.addEventListener('click', options.onAddShared);
            headingRow.appendChild(addBtn);
        }
        treeEl.appendChild(headingRow);
        if (data.shared) data.shared.forEach(s => renderTree(s, treeEl, currentPath, 0, 'shared', options));
    }

    if (data.is_admin && !options.hideConfig) {
        const configHeading = document.createElement('h2');
        configHeading.className = 'mt-4 mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-400';
        configHeading.textContent = 'Configuration';
        treeEl.appendChild(configHeading);

        const usersLink = document.createElement('div');
        const isUsersPage = options.activeSection === 'users';
        usersLink.className = 'flex items-center gap-1 px-2 py-1 rounded-md cursor-pointer text-sm ' +
            (isUsersPage ? 'select-none bg-brand-50 text-brand-700 font-medium' : 'text-gray-700 hover:bg-gray-100');
        usersLink.style.paddingLeft = '20px';
        usersLink.innerHTML =
            '<svg class="w-4 h-4 ' + (isUsersPage ? 'text-brand-500' : 'text-gray-400') + ' flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>' +
            '</svg>' +
            '<span class="truncate">Users</span>';
        usersLink.addEventListener('click', () => { window.location.href = '/users/'; });
        treeEl.appendChild(usersLink);
    }
}

// Expose globally for inline onclick handlers in HTML
window.openModal = openModal;
window.closeModal = closeModal;
