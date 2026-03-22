<template>
  <div>
    <!-- My Files section -->
    <h2 class="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-400">My files</h2>
    <tree-node
      v-if="tree"
      :node="tree"
      :current-path="currentPath"
      :depth="0"
      icon-type="folder"
      @share-click="onShareClick"
    />

    <!-- Shared section -->
    <div v-if="isAdmin || (shared && shared.length > 0)">
      <div class="mt-4 mb-2 px-2 flex items-center justify-between">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Shared</h2>
        <button
          v-if="isAdmin"
          class="w-5 h-5 flex items-center justify-center rounded text-gray-400 hover:text-brand-600 hover:bg-gray-100"
          @click="onAddShared"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
        </button>
      </div>
      <tree-node
        v-for="s in shared"
        :key="'shared-' + (s.sf_id || s.url_path)"
        :node="s"
        :current-path="currentPath"
        :depth="0"
        icon-type="shared"
        @share-click="onShareClick"
      />
    </div>

    <!-- Shared with contact section -->
    <div v-if="contacts && contacts.length > 0 || contactGroups && contactGroups.length > 0 || true">
      <div class="mt-4 mb-2 px-2 flex items-center justify-between">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400">Shared with contact</h2>
        <button
          class="w-5 h-5 flex items-center justify-center rounded text-gray-400 hover:text-brand-600 hover:bg-gray-100"
          @click="onAddContact"
          title="Add contact or group"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
        </button>
      </div>
      <!-- Contact groups -->
      <tree-node
        v-for="g in contactGroups"
        :key="'group-' + g.url_path"
        :node="g"
        :current-path="currentPath"
        :depth="0"
        icon-type="shared"
      />
      <!-- Individual contacts -->
      <tree-node
        v-for="c in contacts"
        :key="'contact-' + c.url_path"
        :node="c"
        :current-path="currentPath"
        :depth="0"
        icon-type="contact"
      />
    </div>

    <div v-if="loading" class="flex items-center gap-1 px-2 py-1.5 rounded-md text-gray-400 text-xs">Loading...</div>
  </div>
</template>

<script>
import { defineComponent, ref, onMounted, watch } from 'vue';
import TreeNode from './TreeNode.vue';

export default defineComponent({
  name: 'BrowseSidebar',
  components: { TreeNode },
  props: {
    currentPath: { type: String, default: '' },
    isAdmin: { type: Boolean, default: false },
    onOpenSharedModal: { type: Function, default: null },
    onOpenMembersModal: { type: Function, default: null },
    onOpenContactModal: { type: Function, default: null },
    onOpenGroupModal: { type: Function, default: null },
  },
  setup(props) {
    const tree = ref(null);
    const shared = ref([]);
    const contacts = ref([]);
    const contactGroups = ref([]);
    const loading = ref(true);

    function loadTree() {
      fetch('/api/tree/')
        .then(r => r.json())
        .then(data => {
          tree.value = data.tree || null;
          shared.value = data.shared || [];
          contacts.value = data.contacts || [];
          contactGroups.value = data.contact_groups || [];
          loading.value = false;
        });
    }

    onMounted(() => {
      loadTree();
    });

    // Reload tree when currentPath changes (SPA navigation)
    watch(() => props.currentPath, () => {
      loadTree();
    });

    function onAddShared() {
      if (props.onOpenSharedModal) props.onOpenSharedModal();
    }

    function onAddContact() {
      if (props.onOpenContactModal) props.onOpenContactModal();
    }

    function onAddGroup() {
      if (props.onOpenGroupModal) props.onOpenGroupModal();
    }

    function onShareClick(sfId, sfName) {
      if (props.onOpenMembersModal) props.onOpenMembersModal(sfId, sfName);
    }

    return { tree, shared, contacts, contactGroups, loading, onAddShared, onAddContact, onAddGroup, onShareClick };
  },
});
</script>
