import { getCsrfToken, openModal, closeModal } from './common.js';

// Delete user
function deleteUser(userId, username) {
  if (!confirm('Delete user "' + username + '"? All their files will be deleted.'))
    return;
  fetch('/api/users/' + userId + '/', {
    method: 'DELETE',
    headers: { 'X-CSRFToken': getCsrfToken() },
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.error) {
        alert(data.error);
        return;
      }
      const row = document.querySelector('tr[data-user-id="' + userId + '"]');
      if (row) row.remove();
    });
}
window.deleteUser = deleteUser;

// Add user
document.getElementById('add-user-form').addEventListener('submit', function (e) {
  e.preventDefault();
  const username = document.getElementById('new-user-username').value.trim();
  const first_name = document.getElementById('new-user-first-name').value.trim();
  const last_name = document.getElementById('new-user-last-name').value.trim();
  const email = document.getElementById('new-user-email').value.trim();
  const password = document.getElementById('new-user-password').value.trim();
  const role = document.getElementById('new-user-role').value;
  const errorEl = document.getElementById('add-user-error');
  errorEl.classList.add('hidden');

  fetch('/api/users/create/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
    body: JSON.stringify({ username, first_name, last_name, email, password, role }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.error) {
        errorEl.textContent = data.error;
        errorEl.classList.remove('hidden');
        return;
      }
      location.reload();
    });
});

// Edit user modal
function openEditModal(userId, username, firstName, lastName, email, role, isActive) {
  document.getElementById('edit-user-id').value = userId;
  document.getElementById('edit-user-title').textContent = username;
  document.getElementById('edit-user-first-name').value = firstName || '';
  document.getElementById('edit-user-last-name').value = lastName || '';
  document.getElementById('edit-user-email').value = email || '';
  document.getElementById('edit-user-role').value = role;
  document.getElementById('edit-user-password').value = '';
  document.getElementById('edit-user-active').checked = isActive;
  document.getElementById('edit-user-error').classList.add('hidden');
  openModal('edit-user-modal');
}
window.openEditModal = openEditModal;

function closeEditModal() {
  closeModal('edit-user-modal');
}
window.closeEditModal = closeEditModal;

document.getElementById('edit-user-form').addEventListener('submit', function (e) {
  e.preventDefault();
  const userId = document.getElementById('edit-user-id').value;
  const errorEl = document.getElementById('edit-user-error');
  errorEl.classList.add('hidden');

  const payload = {
    first_name: document.getElementById('edit-user-first-name').value.trim(),
    last_name: document.getElementById('edit-user-last-name').value.trim(),
    email: document.getElementById('edit-user-email').value.trim(),
    role: document.getElementById('edit-user-role').value,
    is_active: document.getElementById('edit-user-active').checked,
  };

  const password = document.getElementById('edit-user-password').value.trim();
  if (password) {
    payload.password = password;
  }

  fetch('/api/users/' + userId + '/update/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
    body: JSON.stringify(payload),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.error) {
        errorEl.textContent = data.error;
        errorEl.classList.remove('hidden');
        return;
      }
      closeEditModal();
      location.reload();
    });
});
