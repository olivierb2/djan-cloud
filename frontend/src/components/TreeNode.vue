<template>
  <div>
    <a
      :href="node.url_path ? '/browse/' + node.url_path : '/browse/'"
      draggable="false"
      class="group flex items-center gap-1 px-2 py-1 rounded-md cursor-pointer text-sm select-none no-underline transition-colors"
      :class="[
        isActive ? 'bg-brand-50 text-brand-700 font-medium' : 'text-gray-700 hover:bg-gray-100',
        isDropTarget ? 'ring-2 ring-brand-400 bg-brand-50' : ''
      ]"
      :style="{ paddingLeft: (depth * 12 + 8) + 'px' }"
      @click.prevent="onNavigate"
      @dragover.prevent="onDragOver"
      @dragleave="onDragLeave"
      @drop.prevent="onDrop"
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

      <!-- Settings button for root shared folders -->
      <svg
        v-if="iconType === 'shared' && depth === 0 && node.sf_id"
        class="w-3.5 h-3.5 text-gray-400 hover:text-gray-600 flex-shrink-0 cursor-pointer hidden group-hover:block"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        @click.prevent.stop="$emit('share-click', node.sf_id, node.name)"
      >
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
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
    const dragItem = inject('dragItem', ref(null));
    const dropTargetId = inject('dropTargetId', ref(null));
    const onDropOnFolder = inject('onDropOnFolder', null);

    const hasChildren = computed(() => props.node.children && props.node.children.length > 0);

    const isActive = computed(() => props.node.url_path === props.currentPath);

    // Auto-expand nodes that are on the current path
    const isOnPath = computed(() =>
      props.currentPath === props.node.url_path ||
      props.currentPath.startsWith(props.node.url_path ? props.node.url_path + '/' : '')
    );

    const isOpen = ref(isOnPath.value && hasChildren.value);

    const nodeDropId = computed(() => 'tree-' + (props.node.id || props.node.url_path));
    const isDropTarget = computed(() => dropTargetId.value === nodeDropId.value);

    // Navigate using injected function or fall back to page navigation
    function onNavigate() {
      const path = props.node.url_path || '';
      if (navigateToFolder) {
        navigateToFolder(path);
      } else {
        window.location.href = '/browse/' + (path || '');
      }
    }

    function onDragOver(e) {
      if (!dragItem.value || !props.node.id) return;
      if (dragItem.value.type === 'folder' && dragItem.value.id === props.node.id) return;
      e.dataTransfer.dropEffect = (e.ctrlKey || e.metaKey) ? 'copy' : 'move';
      dropTargetId.value = nodeDropId.value;
    }

    function onDragLeave() {
      if (dropTargetId.value === nodeDropId.value) dropTargetId.value = null;
    }

    function onDrop(e) {
      if (!dragItem.value || !props.node.id || !onDropOnFolder) return;
      dropTargetId.value = null;
      onDropOnFolder(e, props.node.id);
    }

    return { hasChildren, isActive, isOpen, isDropTarget, onNavigate, onDragOver, onDragLeave, onDrop };
  },
});
</script>
