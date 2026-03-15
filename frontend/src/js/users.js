import { getCsrfToken } from './common.js';

// Delete user
function deleteUser(userId, username) {
    if (!confirm('Delete user "' + username + '"? All their files will be deleted.')) return;
    fetch('/api/users/' + userId + '/', {
        method: 'DELETE',
        headers: {'X-CSRFToken': getCsrfToken()}
    }).then(r => r.json()).then(data => {
        if (data.error) { alert(data.error); return; }
        const row = document.querySelector('tr[data-user-id="' + userId + '"]');
        if (row) row.remove();
    });
}
window.deleteUser = deleteUser;

// Add user
document.getElementById('add-user-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const username = document.getElementById('new-user-username').value.trim();
    const password = document.getElementById('new-user-password').value.trim();
    const role = document.getElementById('new-user-role').value;
    const errorEl = document.getElementById('add-user-error');
    errorEl.classList.add('hidden');

    fetch('/api/users/create/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({username, password, role})
    }).then(r => r.json()).then(data => {
        if (data.error) {
            errorEl.textContent = data.error;
            errorEl.classList.remove('hidden');
            return;
        }
        location.reload();
    });
});
