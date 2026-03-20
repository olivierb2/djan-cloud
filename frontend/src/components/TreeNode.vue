<template>
  <div>
    <a
      :href="node.url_path ? '/browse/' + node.url_path : '/browse/'"
      class="flex items-center gap-1 px-2 py-1 rounded-md cursor-pointer text-sm select-none no-underline"
      :class="isActive ? 'bg-brand-50 text-brand-700 font-medium' : 'text-gray-700 hover:bg-gray-100'"
      :style="{ paddingLeft: (depth * 12 + 8) + 'px' }"
      @click.prevent="onNavigate"
    >
      <!-- Toggle chevron -->
      <svg
        v-if="hasChildren"
        class="w-3 h-3 text-gray-400 flex-shrink-0 cursor-pointer transition-transform duration-150"
        :class="{ 'rotate-90': isOpen }"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        @click.prevent.stop="isOpen = !isOpen"
      >
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
      </svg>
      <span v-else class="w-3 flex-shrink-0" />

      <!-- Folder icon -->
      <svg
        v-if="iconType === 'folder'"
        class="w-4 h-4 text-yellow-400 flex-shrink-0"
        fill="currentColor"
        viewBox="0 0 24 24"
      >
        <path d="M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z" />
      </svg>

      <!-- Shared icon -->
      <svg
        v-else-if="iconType === 'shared'"
        class="w-4 h-4 text-brand-500 flex-shrink-0"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"
        />
      </svg>

      <!-- Contact icon -->
      <svg
        v-else-if="iconType === 'contact'"
        class="w-4 h-4 text-teal-500 flex-shrink-0"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
        />
      </svg>

      <!-- Folder name -->
      <span class="truncate flex-1">{{ node.name }}</span>

      <!-- Share button for root shared folders -->
      <svg
        v-if="iconType === 'shared' && depth === 0 && node.sf_id"
        class="w-3.5 h-3.5 text-gray-400 hover:text-brand-600 flex-shrink-0 cursor-pointer"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        @click.prevent.stop="$emit('share-click', node.sf_id, node.name)"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"
        />
      </svg>
    </a>

    <!-- Children -->
    <div v-if="hasChildren && isOpen">
      <tree-node
        v-for="child in node.children"
        :key="child.url_path"
        :node="child"
        :current-path="currentPath"
        :depth="depth + 1"
        icon-type="folder"
        @share-click="(sfId, sfName) => $emit('share-click', sfId, sfName)"
      />
    </div>
  </div>
</template>

<script>
import { defineComponent, ref, computed, inject } from 'vue';

export default defineComponent({
  name: 'TreeNode',
  props: {
    node: {
      type: Object,
      required: true,
    },
    currentPath: {
      type: String,
      default: '',
    },
    depth: {
      type: Number,
      default: 0,
    },
    iconType: {
      type: String,
      default: 'folder',
      validator: v => ['folder', 'shared', 'contact'].includes(v),
    },
  },
  emits: ['share-click'],
  setup(props) {
    const navigateToFolder = inject('navigateToFolder', null);

    const hasChildren = computed(() => props.node.children && props.node.children.length > 0);

    const isActive = computed(() => props.node.url_path === props.currentPath);

    // Auto-expand nodes that are on the current path
    const isOnPath = computed(() =>
      props.currentPath === props.node.url_path ||
      props.currentPath.startsWith(props.node.url_path ? props.node.url_path + '/' : '')
    );

    const isOpen = ref(isOnPath.value && hasChildren.value);

    // Navigate using injected function or fall back to page navigation
    function onNavigate() {
      const path = props.node.url_path || '';
      if (navigateToFolder) {
        navigateToFolder(path);
      } else {
        window.location.href = '/browse/' + (path || '');
      }
    }

    return { hasChildren, isActive, isOpen, onNavigate };
  },
});
</script>
