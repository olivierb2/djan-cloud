<template>
  <teleport to="body">
    <div v-if="visible" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="close">
      <div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl" @click.stop>
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Add contact or group</h3>

        <!-- Search -->
        <div class="relative mb-4">
          <input
            ref="searchInput"
            v-model="query"
            type="text"
            placeholder="Search contacts and groups..."
            class="block w-full rounded-lg border border-gray-300 pl-9 pr-3 py-2 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
            @input="onSearch"
            @keydown.esc="close"
          >
          <svg class="w-4 h-4 absolute left-3 top-2.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
        </div>

        <div class="max-h-72 overflow-y-auto rounded-lg border border-gray-200">
          <!-- Groups section -->
          <div v-if="filteredGroups.length > 0">
            <div class="px-3 py-1.5 bg-gray-50 border-b border-gray-100 text-xs font-semibold uppercase tracking-wider text-gray-400">Groups</div>
            <button
              v-for="g in filteredGroups"
              :key="'g-' + g.id"
              type="button"
              class="flex w-full items-center gap-3 px-4 py-2 text-left hover:bg-gray-50 transition-colors border-b border-gray-100"
              @click="selectGroup(g.id)"
            >
              <svg class="w-5 h-5 text-brand-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
              </svg>
              <div class="flex-1 min-w-0">
                <div class="text-sm font-medium text-gray-900 truncate">{{ g.name }}</div>
                <div class="text-xs text-gray-500">{{ g.count }} contact{{ g.count !== 1 ? 's' : '' }}</div>
              </div>
            </button>
          </div>

          <!-- Contacts section -->
          <div v-if="results && results.length > 0">
            <div class="px-3 py-1.5 bg-gray-50 border-b border-gray-100 text-xs font-semibold uppercase tracking-wider text-gray-400">Contacts</div>
            <button
              v-for="c in results"
              :key="'c-' + c.id"
              type="button"
              class="flex w-full items-center gap-3 px-4 py-2 text-left hover:bg-gray-50 transition-colors border-b border-gray-100"
              @click="selectContact(c.id)"
            >
              <svg class="w-5 h-5 text-teal-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
              </svg>
              <div class="flex-1 min-w-0">
                <div class="text-sm font-medium text-gray-900 truncate">{{ c.name || c.email }}</div>
                <div v-if="c.email" class="text-xs text-gray-500 truncate">{{ c.email }}</div>
              </div>
            </button>
          </div>

          <!-- Empty states -->
          <div v-if="query && results && results.length === 0 && filteredGroups.length === 0"
               class="px-4 py-6 text-sm text-gray-400 text-center">No results found</div>
          <div v-if="!query && groups.length === 0"
               class="px-4 py-6 text-sm text-gray-400 text-center">Type to search contacts, or create groups in Contacts</div>
        </div>

        <div class="flex justify-end mt-4">
          <button type="button" @click="close"
                  class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
        </div>
      </div>
    </div>
  </teleport>
</template>

<script>
import { defineComponent, ref, computed, nextTick } from 'vue';

export default defineComponent({
  name: 'ContactSearchModal',
  props: {
    csrfToken: { type: String, default: '' },
  },
  setup(props) {
    const visible = ref(false);
    const query = ref('');
    const results = ref(null);
    const groups = ref([]);
    const searchInput = ref(null);
    let searchTimer = null;

    const filteredGroups = computed(() => {
      const q = query.value.trim().toLowerCase();
      if (!q) return groups.value;
      return groups.value.filter(g => g.name.toLowerCase().includes(q));
    });

    function open() {
      visible.value = true;
      query.value = '';
      results.value = null;
      // Load groups
      fetch('/api/contact-groups/list/', {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then(r => r.json())
        .then(data => { groups.value = data; })
        .catch(() => {});
      nextTick(() => {
        if (searchInput.value) searchInput.value.focus();
      });
    }

    function close() {
      visible.value = false;
    }

    function onSearch() {
      clearTimeout(searchTimer);
      const q = query.value.trim();
      if (q.length < 1) { results.value = null; return; }
      searchTimer = setTimeout(() => {
        fetch(`/api/contacts/search/?q=${encodeURIComponent(q)}`)
          .then(r => r.json())
          .then(data => { results.value = data; });
      }, 300);
    }

    function selectContact(contactId) {
      fetch('/api/contact-folders/create/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
        body: JSON.stringify({ contact_id: contactId }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) {
            alert(data.error);
          } else {
            close();
            window.location.href = '/browse/' + data.url_path;
          }
        })
        .catch(err => console.error('Error creating contact folder:', err));
    }

    function selectGroup(groupId) {
      fetch('/api/contact-group-folders/create/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
        body: JSON.stringify({ group_id: groupId }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) {
            alert(data.error);
          } else {
            close();
            window.location.href = '/browse/' + data.url_path;
          }
        })
        .catch(err => console.error('Error creating group folder:', err));
    }

    return { visible, query, results, groups, filteredGroups, searchInput, open, close, onSearch, selectContact, selectGroup };
  },
});
</script>
