<template>
  <div class="flex flex-1 overflow-hidden">

    <!-- Sidebar -->
    <aside class="hidden lg:flex w-60 flex-col border-r border-gray-200 bg-white overflow-y-auto">
      <div class="px-3 py-4">
        <browse-sidebar
          :current-path="currentPath"
          :is-admin="isAdmin"
          :on-open-shared-modal="() => showSharedFolderModal = true"
          :on-open-members-modal="openMembersModal"
          :on-open-contact-modal="() => showContactModal = true"
        />
      </div>
    </aside>

    <!-- Main content -->
    <main class="flex-1 overflow-y-auto p-4 lg:p-6">

      <!-- Search bar -->
      <div class="mb-4 flex items-center justify-between">
        <div class="relative" ref="searchContainer">
          <input
            type="text"
            v-model="searchQuery"
            placeholder="Search files and folders..."
            class="w-64 rounded-lg border border-gray-300 pl-9 pr-3 py-1.5 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
            @input="onSearch"
            @keydown.esc="closeSearch"
          >
          <svg class="w-4 h-4 absolute left-3 top-2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <!-- Search results dropdown -->
          <div
            v-if="searchResults !== null"
            class="absolute top-full left-0 mt-2 w-96 max-h-96 overflow-y-auto rounded-lg border border-gray-200 bg-white shadow-xl z-50"
          >
            <div v-if="searchResults.length === 0" class="p-4 text-sm text-gray-400 text-center">No results found</div>
            <template v-else>
              <a
                v-for="item in searchResults"
                :key="item.url"
                :href="item.type === 'folder' ? undefined : item.url"
                class="flex items-start gap-3 px-4 py-3 border-b border-gray-100 hover:bg-gray-50 transition-colors cursor-pointer"
                @click.prevent="onSearchResultClick(item)"
              >
                <!-- Folder icon -->
                <svg v-if="item.type === 'folder'" class="w-5 h-5 text-yellow-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z"/>
                </svg>
                <!-- Image icon -->
                <svg v-else-if="item.content_type && item.content_type.includes('image')" class="w-5 h-5 text-green-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                </svg>
                <!-- Markdown icon -->
                <svg v-else-if="item.name && item.name.toLowerCase().endsWith('.md')" class="w-5 h-5 text-blue-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                </svg>
                <!-- Default file icon -->
                <svg v-else class="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                <div class="flex-1 min-w-0">
                  <div class="font-medium text-sm text-gray-900 truncate">{{ item.name }}</div>
                  <div class="text-xs text-gray-500 truncate">{{ item.path }}</div>
                  <div class="text-xs text-gray-400 mt-0.5">{{ item.location }}</div>
                </div>
              </a>
            </template>
          </div>
        </div>

        <!-- Breadcrumbs -->
        <div class="hidden sm:flex items-center gap-1 text-sm text-gray-500">
          <a href="#" class="hover:text-brand-600 rounded px-1 transition-colors"
             :class="{ 'ring-2 ring-brand-400 bg-brand-50': dropTargetId === 'bc-home' }"
             @click.prevent="navigateToFolder('')"
             @dragover.prevent="dragItem && (dropTargetId = 'bc-home')"
             @dragleave="dropTargetId === 'bc-home' && (dropTargetId = null)"
             @drop.prevent="onDropOnFolder($event, null)">Home</a>
          <template v-for="(part, idx) in breadcrumbs" :key="part.path">
            <svg class="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
            </svg>
            <span v-if="idx === breadcrumbs.length - 1" class="text-gray-900 font-medium">{{ part.name }}</span>
            <a v-else href="#" class="hover:text-brand-600 rounded px-1 transition-colors"
               :class="{ 'ring-2 ring-brand-400 bg-brand-50': dropTargetId === 'bc-' + part.id }"
               @click.prevent="navigateToFolder(part.path)"
               @dragover.prevent="dragItem && (dropTargetId = 'bc-' + part.id)"
               @dragleave="dropTargetId === 'bc-' + part.id && (dropTargetId = null)"
               @drop.prevent="onDropOnFolder($event, part.id)">{{ part.name }}</a>
          </template>
        </div>
      </div>

      <!-- Toolbar -->
      <div class="mb-4 flex flex-wrap items-center gap-2">
        <!-- Back button -->
        <button
          v-if="parentPath !== null"
          class="inline-flex items-center gap-1 rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
          @click="navigateToFolder(parentPath)"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
          </svg>
          Back
        </button>

        <template v-if="canWrite">
          <!-- New dropdown -->
          <div class="relative" ref="newDropdown">
            <button
              class="inline-flex items-center gap-1.5 rounded-lg bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700 transition-colors"
              @click="showNewMenu = !showNewMenu"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
              </svg>
              New
              <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
              </svg>
            </button>
            <div v-if="showNewMenu" class="absolute left-0 mt-1 w-48 rounded-lg border border-gray-200 bg-white py-1 shadow-lg z-20">
              <button class="flex w-full items-center gap-2 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50" @click="showNewMenu = false; showCreateFolderModal = true">
                <svg class="w-4 h-4 text-yellow-500" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z"/>
                </svg>
                New folder
              </button>
              <button class="flex w-full items-center gap-2 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50" @click="showNewMenu = false; showCreateFileModal = true">
                <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                New text file
              </button>
            </div>
          </div>

          <!-- Upload button -->
          <button
            class="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
            @click="$refs.fileInput.click()"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
            </svg>
            Upload
          </button>
          <input type="file" ref="fileInput" class="hidden" @change="onFileSelected">
        </template>
      </div>

      <!-- Drop zone overlay -->
      <div
        v-if="canWrite && showDropZone"
        class="mb-4 rounded-xl border-2 border-dashed border-brand-400 bg-brand-50 p-8 text-center text-brand-600 font-medium"
      >
        Drop files here to upload
      </div>

      <!-- Loading -->
      <div v-if="loading" class="flex items-center justify-center py-12">
        <div class="text-sm text-gray-400">Loading...</div>
      </div>

      <!-- File table -->
      <div v-else class="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
        <table class="w-full text-[13px]">
          <thead>
            <tr class="border-b border-gray-100 bg-gray-50/50 text-xs font-medium uppercase tracking-wider text-gray-500">
              <th class="px-4 py-3 text-left">Name</th>
              <th class="px-4 py-3 text-left hidden sm:table-cell">{{ isContactsRoot ? 'Email' : 'Type' }}</th>
              <th class="px-4 py-3 text-left hidden md:table-cell">{{ isContactsRoot ? 'Organisation' : 'Modified' }}</th>
              <th class="px-4 py-3 text-right hidden sm:table-cell">{{ isContactsRoot ? 'Phone' : 'Size' }}</th>
              <th class="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">

            <!-- Contacts root view -->
            <template v-if="isContactsRoot">
              <tr v-for="contact in contactsList" :key="contact.url_path" class="group hover:bg-gray-50/50 transition-colors">
                <td class="px-4 py-1.5">
                  <a href="#" class="inline-flex items-center gap-2 font-medium text-gray-900 hover:text-brand-600" @click.prevent="navigateToFolder(contact.url_path)">
                    <svg class="w-5 h-5 text-teal-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                    </svg>
                    {{ contact.fn || contact.uid }}
                  </a>
                </td>
                <td class="px-4 py-1.5 text-gray-500 hidden sm:table-cell">{{ contact.email || '\u2014' }}</td>
                <td class="px-4 py-1.5 text-gray-500 hidden md:table-cell">{{ contact.org || '\u2014' }}</td>
                <td class="px-4 py-1.5 text-gray-400 text-right hidden sm:table-cell">{{ contact.tel || '\u2014' }}</td>
                <td class="px-4 py-1.5 text-right"></td>
              </tr>
              <tr v-if="!contactsList || contactsList.length === 0">
                <td colspan="5" class="px-4 py-12 text-center text-sm text-gray-400">
                  <svg class="mx-auto mb-2 w-10 h-10 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                  </svg>
                  No contact folders yet
                </td>
              </tr>
            </template>

            <!-- Shared root view -->
            <template v-else-if="isSharedRoot">
              <tr v-for="sf in sharedFolders" :key="sf.url_path" class="group hover:bg-gray-50/50 transition-colors">
                <td class="px-4 py-1.5">
                  <a href="#" class="inline-flex items-center gap-2 font-medium text-gray-900 hover:text-brand-600" @click.prevent="navigateToFolder(sf.url_path)">
                    <svg class="w-5 h-5 text-brand-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                    </svg>
                    {{ sf.name }}
                  </a>
                </td>
                <td class="px-4 py-1.5 text-gray-500 hidden sm:table-cell">Shared folder</td>
                <td class="px-4 py-1.5 text-gray-500 hidden md:table-cell">{{ formatDate(sf.created_at) }}</td>
                <td class="px-4 py-1.5 text-gray-400 text-right hidden sm:table-cell">
                  <span
                    class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium"
                    :class="{
                      'bg-purple-50 text-purple-700': sf.permission === 'admin',
                      'bg-green-50 text-green-700': sf.permission === 'write',
                      'bg-gray-100 text-gray-600': sf.permission !== 'admin' && sf.permission !== 'write',
                    }"
                  >
                    {{ sf.permission }}
                  </span>
                </td>
                <td class="px-4 py-1.5 text-right"></td>
              </tr>
              <tr v-if="!sharedFolders || sharedFolders.length === 0">
                <td colspan="5" class="px-4 py-12 text-center text-sm text-gray-400">
                  <svg class="mx-auto mb-2 w-10 h-10 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                  </svg>
                  No shared folders
                </td>
              </tr>
            </template>

            <!-- Normal folder view: subfolders then files -->
            <template v-else>
              <tr v-for="folder in subfolders" :key="'folder-' + folder.id"
                  class="group hover:bg-gray-50/50 transition-colors"
                  :class="{ 'ring-2 ring-brand-400 bg-brand-50': dropTargetId === folder.id }"
                  :draggable="canWrite"
                  @dragstart="onDragStartItem($event, 'folder', folder.id, folder.name)"
                  @dragend="onDragEndItem"
                  @dragover="onDragOverFolder($event, folder.id)"
                  @dragleave="onDragLeaveFolder($event, folder.id)"
                  @drop="onDropOnFolder($event, folder.id)">
                <td class="px-4 py-1.5">
                  <a href="#" class="inline-flex items-center gap-2 font-medium text-gray-900 hover:text-brand-600" @click.prevent="navigateToFolder(folder.url_path)">
                    <svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z"/>
                    </svg>
                    {{ folder.name }}
                  </a>
                </td>
                <td class="px-4 py-1.5 text-gray-500 hidden sm:table-cell">Folder</td>
                <td class="px-4 py-1.5 text-gray-500 hidden md:table-cell">{{ formatDate(folder.updated_at) }}</td>
                <td class="px-4 py-1.5 text-gray-400 text-right hidden sm:table-cell">&mdash;</td>
                <td class="px-4 py-1.5 text-right">
                  <div v-if="canWrite" class="inline-flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button title="Rename" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100" @click="openRenameModal('folder', folder.id, folder.name)">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                      </svg>
                    </button>
                    <button @click="openMoveModal('folder', folder.id, folder.name)" title="Move" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/>
                      </svg>
                    </button>
                    <button title="Delete" class="rounded p-1 text-gray-400 hover:text-red-600 hover:bg-red-50" @click="deleteItem('folder', folder.id, folder.name)">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>

              <tr v-for="file in files" :key="'file-' + file.id" :id="'file-' + file.id"
                  class="group hover:bg-gray-50/50 transition-colors"
                  :draggable="canWrite"
                  @dragstart="onDragStartItem($event, 'file', file.id, file.display_name)"
                  @dragend="onDragEndItem">
                <td class="px-4 py-1.5">
                  <!-- Markdown files link to editor -->
                  <a
                    v-if="file.display_name && file.display_name.toLowerCase().endsWith('.md')"
                    :href="'/editor/' + file.id + '/'"
                    class="inline-flex items-center gap-2 font-medium text-gray-900 hover:text-brand-600"
                  >
                    <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                    </svg>
                    {{ file.display_name }}
                  </a>
                  <!-- Other files link to preview -->
                  <a
                    v-else
                    :href="'/preview/' + file.id + '/'"
                    class="inline-flex items-center gap-2 font-medium text-gray-900 hover:text-brand-600"
                  >
                    <!-- Image icon -->
                    <svg v-if="file.content_type && file.content_type.includes('image')" class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>
                    </svg>
                    <!-- PDF icon -->
                    <svg v-else-if="file.content_type && file.content_type.includes('pdf')" class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
                    </svg>
                    <!-- Default file icon -->
                    <svg v-else class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                    </svg>
                    {{ file.display_name }}
                  </a>
                </td>
                <td class="px-4 py-1.5 text-gray-500 hidden sm:table-cell">{{ file.content_type || 'File' }}</td>
                <td class="px-4 py-1.5 text-gray-500 hidden md:table-cell">{{ formatDate(file.updated_at) }}</td>
                <td class="px-4 py-1.5 text-gray-500 text-right hidden sm:table-cell">{{ formatSize(file.size) }}</td>
                <td class="px-4 py-1.5 text-right">
                  <div class="inline-flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <a :href="'/download/' + file.id + '/'" title="Download" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                      </svg>
                    </a>
                    <template v-if="canWrite">
                      <button title="Rename" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100" @click="openRenameModal('file', file.id, file.display_name)">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                        </svg>
                      </button>
                      <button @click="openMoveModal('file', file.id, file.display_name)" title="Move" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/>
                        </svg>
                      </button>
                      <button title="Delete" class="rounded p-1 text-gray-400 hover:text-red-600 hover:bg-red-50" @click="deleteItem('file', file.id, file.display_name)">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                        </svg>
                      </button>
                    </template>
                  </div>
                </td>
              </tr>

              <!-- Empty state -->
              <tr v-if="subfolders.length === 0 && files.length === 0">
                <td colspan="5" class="px-4 py-12 text-center text-sm text-gray-400">
                  <svg class="mx-auto mb-2 w-10 h-10 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                  </svg>
                  This folder is empty
                </td>
              </tr>
            </template>

          </tbody>
        </table>
      </div>
    </main>
  </div>

  <!-- Create folder modal -->
  <teleport to="body">
    <div v-if="showCreateFolderModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="showCreateFolderModal = false">
      <div class="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl" @click.stop>
        <h3 class="text-lg font-semibold text-gray-900 mb-4">New folder</h3>
        <form @submit.prevent="createFolder">
          <input
            v-model="newFolderName"
            type="text"
            required
            maxlength="255"
            placeholder="Folder name"
            class="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none mb-4"
            ref="folderNameInput"
          >
          <div class="flex justify-end gap-2">
            <button type="button" @click="showCreateFolderModal = false" class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
            <button type="submit" class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700">Create</button>
          </div>
        </form>
      </div>
    </div>
  </teleport>

  <!-- Create text file modal -->
  <teleport to="body">
    <div v-if="showCreateFileModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="showCreateFileModal = false">
      <div class="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl" @click.stop>
        <h3 class="text-lg font-semibold text-gray-900 mb-4">New text file</h3>
        <form @submit.prevent="createTextFile">
          <input
            v-model="newFileName"
            type="text"
            required
            maxlength="255"
            placeholder="filename.txt"
            class="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none mb-4"
            ref="fileNameInput"
          >
          <div class="flex justify-end gap-2">
            <button type="button" @click="showCreateFileModal = false" class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
            <button type="submit" class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700">Create</button>
          </div>
        </form>
      </div>
    </div>
  </teleport>

  <!-- Rename modal -->
  <teleport to="body">
    <div v-if="showRenameModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="showRenameModal = false">
      <div class="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl" @click.stop>
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Rename</h3>
        <form @submit.prevent="submitRename">
          <input
            v-model="renameNewName"
            type="text"
            required
            class="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none mb-4"
            ref="renameInput"
          >
          <div class="flex justify-end gap-2">
            <button type="button" @click="showRenameModal = false" class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
            <button type="submit" class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700">Rename</button>
          </div>
        </form>
      </div>
    </div>
  </teleport>

  <!-- Shared folder create modal -->
  <teleport to="body">
    <div v-if="showSharedFolderModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="showSharedFolderModal = false">
      <div class="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl" @click.stop>
        <h3 class="text-lg font-semibold text-gray-900 mb-4">New shared folder</h3>
        <input
          v-model="sharedFolderName"
          type="text"
          placeholder="Folder name"
          maxlength="255"
          class="block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none mb-4"
          ref="sharedFolderInput"
          @keydown.enter.prevent="createSharedFolder"
        >
        <div class="flex justify-end gap-2">
          <button type="button" @click="showSharedFolderModal = false" class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
          <button type="button" @click="createSharedFolder" class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700">Create</button>
        </div>
      </div>
    </div>
  </teleport>

  <!-- Members modal -->
  <teleport to="body">
    <div v-if="showMembersModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="showMembersModal = false">
      <div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl" @click.stop>
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Members &mdash; {{ membersModalTitle }}</h3>
        <div class="mb-4 max-h-60 overflow-y-auto divide-y divide-gray-100">
          <div v-if="membersLoading" class="text-sm text-gray-400 py-2">Loading...</div>
          <div v-for="m in members" :key="m.user_id" class="flex items-center gap-2 py-1.5">
            <span class="flex-1 text-sm text-gray-700">{{ m.username }}</span>
            <select
              :value="m.permission"
              class="rounded border border-gray-300 text-xs px-1.5 py-1"
              @change="updateMember(m.user_id, $event.target.value)"
            >
              <option value="read">Read</option>
              <option value="write">Write</option>
              <option value="admin">Admin</option>
            </select>
            <button class="text-gray-400 hover:text-red-600" title="Remove" @click="removeMember(m.user_id)">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </button>
          </div>
        </div>
        <div class="flex items-center gap-2 border-t border-gray-100 pt-4">
          <select v-model="addMemberUserId" class="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm">
            <option value="">Add a user...</option>
            <option v-for="u in allUsers" :key="u.id" :value="u.id">{{ u.username }}</option>
          </select>
          <button type="button" @click="addMember" class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700">Add</button>
        </div>
        <div class="flex justify-end mt-4">
          <button type="button" @click="showMembersModal = false" class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Close</button>
        </div>
      </div>
    </div>
  </teleport>

  <!-- Contact search modal -->
  <contact-search-modal ref="contactModal" :csrf-token="csrfToken" />

  <!-- Move picker modal -->
  <teleport to="body">
    <div v-if="showMoveModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="showMoveModal = false">
      <div class="w-[40rem] rounded-xl bg-white shadow-xl flex flex-col" style="max-height: 80vh" @click.stop>
        <div class="flex items-center justify-between border-b border-gray-200 px-5 py-3">
          <h3 class="text-lg font-semibold text-gray-900">
            Move <span class="text-gray-500">{{ moveItemName }}</span>
          </h3>
          <button type="button" @click="showMoveModal = false" class="rounded p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
        <!-- Breadcrumb -->
        <div class="border-b border-gray-100 px-5 py-2 flex items-center gap-1 text-sm text-gray-500 overflow-x-auto">
          <template v-for="(bc, i) in moveBreadcrumbs" :key="bc.id">
            <svg v-if="i > 0" class="w-3 h-3 text-gray-300 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
            <button type="button" @click="navigateMovePicker(bc.id)" class="hover:text-brand-600 whitespace-nowrap">{{ bc.name }}</button>
          </template>
        </div>
        <!-- Items -->
        <div class="flex-1 overflow-y-auto">
          <div v-if="moveIsRoot">
            <div class="px-4 py-2 bg-gray-50 border-b border-gray-100">
              <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">My files</span>
            </div>
          </div>
          <div class="divide-y divide-gray-100">
            <div v-for="item in moveSubfolders" :key="item.id"
                 @click="navigateMovePicker(item.id)"
                 class="flex items-center gap-3 px-4 py-1.5 hover:bg-gray-50 cursor-pointer">
              <svg class="w-5 h-5 text-yellow-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
              </svg>
              <span class="text-sm text-gray-700">{{ item.name }}</span>
              <svg class="w-4 h-4 text-gray-300 ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
            </div>
          </div>

          <!-- Shared section -->
          <template v-if="moveShared.length">
            <div class="px-4 py-2 bg-gray-50 border-y border-gray-100">
              <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">Shared</span>
            </div>
            <div class="divide-y divide-gray-100">
              <div v-for="item in moveShared" :key="'s'+item.id"
                   @click="navigateMovePicker(item.id)"
                   class="flex items-center gap-3 px-4 py-1.5 hover:bg-gray-50 cursor-pointer">
                <svg class="w-5 h-5 text-brand-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">{{ item.name }}</span>
              </div>
            </div>
          </template>

          <!-- Contacts section -->
          <template v-if="moveContacts.length">
            <div class="px-4 py-2 bg-gray-50 border-y border-gray-100">
              <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">Shared with contact</span>
            </div>
            <div class="divide-y divide-gray-100">
              <div v-for="item in moveContacts" :key="'c'+item.id"
                   @click="navigateMovePicker(item.id)"
                   class="flex items-center gap-3 px-4 py-1.5 hover:bg-gray-50 cursor-pointer">
                <svg class="w-5 h-5 text-teal-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">{{ item.name }}</span>
              </div>
            </div>
          </template>

          <div v-if="!moveSubfolders.length && !moveShared.length && !moveContacts.length" class="px-4 py-8 text-center text-sm text-gray-400">No subfolders</div>
        </div>
        <div class="border-t border-gray-200 px-5 py-3 flex justify-end gap-2">
          <button type="button" @click="showMoveModal = false"
                  class="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Cancel</button>
          <button type="button" @click="confirmMove" :disabled="moveDestinationId === null"
                  class="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
            Move here
          </button>
        </div>
      </div>
    </div>
  </teleport>

  <!-- Toast notifications -->
  <teleport to="body">
    <div class="fixed bottom-4 right-4 z-50 space-y-2">
      <div
        v-for="toast in toasts"
        :key="toast.id"
        class="rounded-lg px-4 py-3 text-sm shadow-lg"
        :class="{
          'bg-green-50 text-green-800 border border-green-200': toast.type === 'success',
          'bg-red-50 text-red-800 border border-red-200': toast.type === 'error',
          'bg-blue-50 text-blue-800 border border-blue-200': toast.type === 'info',
        }"
      >
        {{ toast.message }}
      </div>
    </div>
  </teleport>
</template>

<script>
import { defineComponent, ref, reactive, onMounted, onBeforeUnmount, provide, nextTick, watch } from 'vue';
import BrowseSidebar from './BrowseSidebar.vue';
import ContactSearchModal from './ContactSearchModal.vue';

export default defineComponent({
  name: 'BrowseApp',
  components: { BrowseSidebar, ContactSearchModal },
  props: {
    initialPath: { type: String, default: '' },
    isAdmin: { type: Boolean, default: false },
    csrfToken: { type: String, default: '' },
  },
  setup(props) {
    // -- State --
    const currentPath = ref(props.initialPath);
    const currentFolder = ref(null);
    const parentPath = ref(null);
    const breadcrumbs = ref([]);
    const subfolders = ref([]);
    const files = ref([]);
    const canWrite = ref(false);
    const isShared = ref(false);
    const isSharedRoot = ref(false);
    const isContactsRoot = ref(false);
    const sharedFolders = ref([]);
    const contactsList = ref([]);
    const loading = ref(true);

    // Toast notifications
    const toasts = ref([]);
    let toastId = 0;

    function addToast(message, type = 'info') {
      const id = ++toastId;
      toasts.value.push({ id, message, type });
      setTimeout(() => {
        toasts.value = toasts.value.filter(t => t.id !== id);
      }, 4000);
    }

    // -- Formatters --
    function formatSize(bytes) {
      if (!bytes) return '—';
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function formatDate(isoString) {
      if (!isoString) return '—';
      const d = new Date(isoString);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
        ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    }

    // -- API helper --
    function apiFetch(url, options = {}) {
      const headers = { ...(options.headers || {}) };
      headers['X-CSRFToken'] = props.csrfToken;
      if (!(options.body instanceof FormData)) {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      }
      return fetch(url, { ...options, headers });
    }

    // -- Navigation --
    function navigateToFolder(path) {
      loading.value = true;
      const apiPath = path ? path : '';
      fetch('/api/browse/' + apiPath)
        .then(r => r.json())
        .then(data => {
          currentPath.value = data.current_path || '';
          currentFolder.value = data.current_folder || null;
          parentPath.value = data.parent_path !== undefined ? data.parent_path : null;
          breadcrumbs.value = data.breadcrumbs || [];
          subfolders.value = data.subfolders || [];
          files.value = data.files || [];
          canWrite.value = !!data.can_write;
          isShared.value = !!data.is_shared;
          isSharedRoot.value = !!data.is_shared_root;
          isContactsRoot.value = !!data.is_contacts_root;
          sharedFolders.value = data.shared_folders || [];
          contactsList.value = data.contacts_list || [];
          loading.value = false;

          // Update browser URL
          const newUrl = '/browse/' + (data.current_path || '');
          history.pushState({ path: data.current_path || '' }, '', newUrl);
        })
        .catch(err => {
          console.error('Navigation error:', err);
          loading.value = false;
          addToast('Failed to load folder', 'error');
        });
    }

    // Provide navigateToFolder so TreeNode and BrowseSidebar children can use it
    // Drag & drop refs (declared early for provide)
    const dragItem = ref(null);
    const dropTargetId = ref(null);

    provide('navigateToFolder', navigateToFolder);
    provide('dragItem', dragItem);
    provide('dropTargetId', dropTargetId);
    provide('onDropOnFolder', (...args) => onDropOnFolder(...args));

    // Handle browser back/forward
    function onPopState(event) {
      const path = (event.state && event.state.path) || '';
      loading.value = true;
      fetch('/api/browse/' + path)
        .then(r => r.json())
        .then(data => {
          currentPath.value = data.current_path || '';
          currentFolder.value = data.current_folder || null;
          parentPath.value = data.parent_path !== undefined ? data.parent_path : null;
          breadcrumbs.value = data.breadcrumbs || [];
          subfolders.value = data.subfolders || [];
          files.value = data.files || [];
          canWrite.value = !!data.can_write;
          isShared.value = !!data.is_shared;
          isSharedRoot.value = !!data.is_shared_root;
          isContactsRoot.value = !!data.is_contacts_root;
          sharedFolders.value = data.shared_folders || [];
          contactsList.value = data.contacts_list || [];
          loading.value = false;
        })
        .catch(() => { loading.value = false; });
    }

    // -- Search --
    const searchQuery = ref('');
    const searchResults = ref(null);
    const searchContainer = ref(null);
    let searchTimer = null;

    function onSearch() {
      clearTimeout(searchTimer);
      const q = searchQuery.value.trim();
      if (q.length < 2) { searchResults.value = null; return; }
      searchTimer = setTimeout(() => {
        fetch('/api/search/?q=' + encodeURIComponent(q))
          .then(r => r.json())
          .then(data => { searchResults.value = data.results || []; });
      }, 300);
    }

    function closeSearch() {
      searchResults.value = null;
    }

    function onSearchResultClick(item) {
      searchResults.value = null;
      searchQuery.value = '';
      if (item.type === 'folder') {
        // Extract path from URL: /browse/some/path -> some/path
        const match = item.url.match(/^\/browse\/(.*)$/);
        const path = match ? match[1] : '';
        navigateToFolder(path);
      } else {
        window.location.href = item.url;
      }
    }

    function onDocumentClick(e) {
      if (searchContainer.value && !searchContainer.value.contains(e.target)) {
        searchResults.value = null;
      }
    }

    // -- New dropdown --
    const showNewMenu = ref(false);
    const newDropdown = ref(null);

    function onDocumentClickDropdown(e) {
      if (newDropdown.value && !newDropdown.value.contains(e.target)) {
        showNewMenu.value = false;
      }
    }

    // -- Modals --
    const showCreateFolderModal = ref(false);
    const showCreateFileModal = ref(false);
    const showRenameModal = ref(false);
    const showSharedFolderModal = ref(false);
    const showMembersModal = ref(false);
    const showContactModal = ref(false);
    const showMoveModal = ref(false);

    // Move picker state
    const moveItemType = ref('');
    const moveItemId = ref(null);
    const moveItemName = ref('');
    const moveDestinationId = ref(null);
    const moveBreadcrumbs = ref([]);
    const moveSubfolders = ref([]);
    const moveShared = ref([]);
    const moveContacts = ref([]);
    const moveIsRoot = ref(true);

    const newFolderName = ref('');
    const newFileName = ref('');
    const renameNewName = ref('');
    const renameType = ref('');
    const renameId = ref(null);
    const sharedFolderName = ref('');

    // Refs for autofocus
    const folderNameInput = ref(null);
    const fileNameInput = ref(null);
    const renameInput = ref(null);
    const sharedFolderInput = ref(null);
    const contactModal = ref(null);

    // Autofocus on modal open
    watch(showCreateFolderModal, (val) => { if (val) { newFolderName.value = ''; nextTick(() => folderNameInput.value?.focus()); } });
    watch(showCreateFileModal, (val) => { if (val) { newFileName.value = ''; nextTick(() => fileNameInput.value?.focus()); } });
    watch(showRenameModal, (val) => { if (val) nextTick(() => { renameInput.value?.focus(); renameInput.value?.select(); }); });
    watch(showSharedFolderModal, (val) => { if (val) { sharedFolderName.value = ''; nextTick(() => sharedFolderInput.value?.focus()); } });
    watch(showContactModal, (val) => { if (val && contactModal.value) contactModal.value.open(); });

    // Close modals on Escape
    function onKeydown(e) {
      if (e.key === 'Escape') {
        showCreateFolderModal.value = false;
        showCreateFileModal.value = false;
        showRenameModal.value = false;
        showSharedFolderModal.value = false;
        showMembersModal.value = false;
      }
    }

    // -- Create folder --
    function createFolder() {
      if (!newFolderName.value.trim()) return;
      apiFetch('/api/folders/create/', {
        method: 'POST',
        body: JSON.stringify({ parent_id: currentFolder.value?.id, name: newFolderName.value.trim() }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          showCreateFolderModal.value = false;
          addToast('Folder created', 'success');
          navigateToFolder(currentPath.value);
        })
        .catch(() => addToast('Failed to create folder', 'error'));
    }

    // -- Create text file --
    function createTextFile() {
      if (!newFileName.value.trim()) return;
      apiFetch('/api/files/create-text/', {
        method: 'POST',
        body: JSON.stringify({ parent_id: currentFolder.value?.id, filename: newFileName.value.trim() }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          showCreateFileModal.value = false;
          addToast('File created', 'success');
          navigateToFolder(currentPath.value);
        })
        .catch(() => addToast('Failed to create file', 'error'));
    }

    // -- Rename --
    function openRenameModal(type, id, name) {
      renameType.value = type;
      renameId.value = id;
      renameNewName.value = name;
      showRenameModal.value = true;
    }

    function submitRename() {
      if (!renameNewName.value.trim()) return;
      apiFetch('/api/rename/' + renameType.value + '/' + renameId.value + '/', {
        method: 'POST',
        body: JSON.stringify({ new_name: renameNewName.value.trim() }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          showRenameModal.value = false;
          addToast('Renamed successfully', 'success');
          navigateToFolder(currentPath.value);
        })
        .catch(() => addToast('Failed to rename', 'error'));
    }

    // -- Delete --
    function deleteItem(type, id, name) {
      const label = type === 'folder' ? "Delete folder '" + name + "' and all its contents?" : "Delete '" + name + "'?";
      if (!confirm(label)) return;
      const url = type === 'folder' ? '/api/folders/' + id + '/delete/' : '/api/files/' + id + '/delete/';
      apiFetch(url, { method: 'DELETE' })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          addToast('Deleted successfully', 'success');
          navigateToFolder(currentPath.value);
        })
        .catch(() => addToast('Failed to delete', 'error'));
    }

    // -- File upload --
    const fileInput = ref(null);

    function onFileSelected(event) {
      const file = event.target.files[0];
      if (!file) return;
      uploadFile(file);
      event.target.value = '';
    }

    function uploadFile(file) {
      const formData = new FormData();
      formData.append('parent_id', currentFolder.value?.id || '');
      formData.append('file', file);
      apiFetch('/api/files/upload/', {
        method: 'POST',
        body: formData,
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          addToast('File uploaded', 'success');
          navigateToFolder(currentPath.value);
        })
        .catch(() => addToast('Failed to upload file', 'error'));
    }

    // -- Drag & drop --
    const showDropZone = ref(false);
    let dragCounter = 0;

    function onDragEnter(e) {
      if (dragItem.value) return; // Internal drag, skip upload overlay
      e.preventDefault();
      dragCounter++;
      if (canWrite.value) showDropZone.value = true;
    }

    function onDragLeave(e) {
      if (dragItem.value) return;
      e.preventDefault();
      dragCounter--;
      if (dragCounter === 0) showDropZone.value = false;
    }

    function onDragOver(e) {
      if (dragItem.value) return;
      e.preventDefault();
    }

    function onDrop(e) {
      if (dragItem.value) return;
      e.preventDefault();
      dragCounter = 0;
      showDropZone.value = false;
      if (!canWrite.value) return;
      const droppedFiles = e.dataTransfer.files;
      if (droppedFiles.length > 0) {
        uploadFile(droppedFiles[0]);
      }
    }

    // -- Shared folder --
    function createSharedFolder() {
      const name = sharedFolderName.value.trim();
      if (!name) return;
      apiFetch('/api/shared-folders/create/', {
        method: 'POST',
        body: JSON.stringify({ name }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          showSharedFolderModal.value = false;
          addToast('Shared folder created', 'success');
          navigateToFolder(currentPath.value);
        })
        .catch(() => addToast('Failed to create shared folder', 'error'));
    }

    // -- Members modal --
    const membersModalTitle = ref('');
    const members = ref([]);
    const membersLoading = ref(false);
    const allUsers = ref([]);
    const addMemberUserId = ref('');
    let currentSfId = null;

    function openMembersModal(sfId, sfName) {
      currentSfId = sfId;
      membersModalTitle.value = sfName;
      showMembersModal.value = true;
      loadMembers();
      if (allUsers.value.length === 0) {
        fetch('/api/users/').then(r => r.json()).then(data => {
          allUsers.value = data.users || [];
        });
      }
    }

    function loadMembers() {
      membersLoading.value = true;
      fetch('/api/shared-folders/' + currentSfId + '/members/')
        .then(r => r.json())
        .then(data => {
          members.value = data.members || [];
          membersLoading.value = false;
        })
        .catch(() => { membersLoading.value = false; });
    }

    function updateMember(userId, permission) {
      apiFetch('/api/shared-folders/' + currentSfId + '/members/', {
        method: 'POST',
        body: JSON.stringify({ user_id: parseInt(userId), permission }),
      }).then(r => r.json());
    }

    function removeMember(userId) {
      apiFetch('/api/shared-folders/' + currentSfId + '/members/' + userId + '/', {
        method: 'DELETE',
      })
        .then(r => r.json())
        .then(() => loadMembers());
    }

    function addMember() {
      if (!addMemberUserId.value) return;
      apiFetch('/api/shared-folders/' + currentSfId + '/members/', {
        method: 'POST',
        body: JSON.stringify({ user_id: parseInt(addMemberUserId.value), permission: 'read' }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.error) { addToast(data.error, 'error'); return; }
          addMemberUserId.value = '';
          loadMembers();
        });
    }

    // -- Move picker --
    function openMoveModal(type, id, name) {
      moveItemType.value = type;
      moveItemId.value = id;
      moveItemName.value = name;
      showMoveModal.value = true;
      navigateMovePicker(null);
    }

    async function navigateMovePicker(folderId) {
      if (moveItemType.value === 'folder' && folderId === moveItemId.value) {
        addToast('Cannot move folder into itself.', 'error');
        return;
      }
      const url = folderId ? `/api/folders/${folderId}/` : '/api/folders/';
      try {
        const r = await fetch(url);
        const data = await r.json();
        moveDestinationId.value = data.folder.id;
        moveBreadcrumbs.value = data.breadcrumbs || [];
        moveSubfolders.value = (data.subfolders || []).filter(
          f => !(moveItemType.value === 'folder' && f.id === moveItemId.value)
        );
        moveShared.value = data.shared_folders || [];
        moveContacts.value = data.contact_folders || [];
        moveIsRoot.value = !!(data.shared_folders || data.contact_folders);
      } catch (err) {
        console.error('Failed to load move picker:', err);
      }
    }

    async function confirmMove() {
      try {
        const r = await apiFetch(`/api/move/${moveItemType.value}/${moveItemId.value}/`, {
          method: 'POST',
          body: JSON.stringify({ destination_folder_id: moveDestinationId.value }),
        });
        const data = await r.json();
        if (data.error) {
          addToast(data.error, 'error');
        } else {
          showMoveModal.value = false;
          addToast('Moved successfully.', 'success');
          navigateToFolder(currentPath.value);
        }
      } catch (err) {
        addToast('Move failed.', 'error');
      }
    }

    // -- Internal drag & drop for moving items --

    function onDragStartItem(e, type, id, name) {
      dragItem.value = { type, id, name };
      e.dataTransfer.effectAllowed = 'copyMove';
      e.dataTransfer.setData('text/plain', `${type}:${id}`);
      // Make the row semi-transparent
      if (e.target && e.target.closest) {
        const row = e.target.closest('tr');
        if (row) setTimeout(() => row.style.opacity = '0.4', 0);
      }
    }

    function onDragEndItem(e) {
      dragItem.value = null;
      dropTargetId.value = null;
      if (e.target && e.target.closest) {
        const row = e.target.closest('tr');
        if (row) row.style.opacity = '';
      }
    }

    function onDragOverFolder(e, folderId) {
      if (!dragItem.value) return;
      // Don't allow dropping a folder on itself
      if (dragItem.value.type === 'folder' && dragItem.value.id === folderId) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = (e.ctrlKey || e.metaKey) ? 'copy' : 'move';
      dropTargetId.value = folderId;
    }

    function onDragLeaveFolder(e, folderId) {
      if (dropTargetId.value === folderId) dropTargetId.value = null;
    }

    async function onDropOnFolder(e, folderId) {
      e.preventDefault();
      if (!dragItem.value) return;
      const item = dragItem.value;
      dragItem.value = null;
      dropTargetId.value = null;
      // If dropping on Home (null), use the root folder id from breadcrumbs
      let destId = folderId;
      if (destId === null && breadcrumbs.value.length > 0) {
        destId = breadcrumbs.value[0].id;
      }
      if (!destId) return;
      const isCopy = (e.ctrlKey || e.metaKey) && item.type === 'file';
      try {
        let url, successMsg;
        if (isCopy) {
          url = `/api/copy/file/${item.id}/`;
          successMsg = `Copied "${item.name}" successfully.`;
        } else {
          url = `/api/move/${item.type}/${item.id}/`;
          successMsg = `Moved "${item.name}" successfully.`;
        }
        const r = await apiFetch(url, {
          method: 'POST',
          body: JSON.stringify({ destination_folder_id: destId }),
        });
        const data = await r.json();
        if (data.error) {
          addToast(data.error, 'error');
        } else {
          addToast(successMsg, 'success');
          navigateToFolder(currentPath.value);
        }
      } catch (err) {
        addToast(isCopy ? 'Copy failed.' : 'Move failed.', 'error');
      }
    }

    // -- Lifecycle --
    onMounted(() => {
      // Initial load
      navigateToFolder(props.initialPath);

      // Replace initial history state
      history.replaceState({ path: props.initialPath }, '', '/browse/' + (props.initialPath || ''));

      // Browser back/forward
      window.addEventListener('popstate', onPopState);

      // Global click handler for closing search and dropdown
      document.addEventListener('click', onDocumentClick);
      document.addEventListener('click', onDocumentClickDropdown);
      document.addEventListener('keydown', onKeydown);

      // Drag & drop on body
      document.body.addEventListener('dragenter', onDragEnter);
      document.body.addEventListener('dragleave', onDragLeave);
      document.body.addEventListener('dragover', onDragOver);
      document.body.addEventListener('drop', onDrop);
    });

    onBeforeUnmount(() => {
      window.removeEventListener('popstate', onPopState);
      document.removeEventListener('click', onDocumentClick);
      document.removeEventListener('click', onDocumentClickDropdown);
      document.removeEventListener('keydown', onKeydown);
      document.body.removeEventListener('dragenter', onDragEnter);
      document.body.removeEventListener('dragleave', onDragLeave);
      document.body.removeEventListener('dragover', onDragOver);
      document.body.removeEventListener('drop', onDrop);
    });

    return {
      // State
      currentPath, currentFolder, parentPath, breadcrumbs,
      subfolders, files, canWrite, isShared, isSharedRoot, isContactsRoot,
      sharedFolders, contactsList, loading, toasts,

      // Formatters
      formatSize, formatDate,

      // Navigation
      navigateToFolder,

      // Search
      searchQuery, searchResults, searchContainer,
      onSearch, closeSearch, onSearchResultClick,

      // New dropdown
      showNewMenu, newDropdown,

      // Modals
      showCreateFolderModal, showCreateFileModal, showRenameModal,
      showSharedFolderModal, showMembersModal, showContactModal,
      newFolderName, newFileName, renameNewName, sharedFolderName,
      folderNameInput, fileNameInput, renameInput, sharedFolderInput,
      contactModal,

      // Actions
      createFolder, createTextFile, openRenameModal, submitRename,
      deleteItem, createSharedFolder,

      // Move picker
      showMoveModal, moveItemName, moveDestinationId,
      moveBreadcrumbs, moveSubfolders, moveShared, moveContacts, moveIsRoot,
      openMoveModal, navigateMovePicker, confirmMove,

      // Upload
      fileInput, onFileSelected, showDropZone,

      // Members
      membersModalTitle, members, membersLoading, allUsers,
      addMemberUserId, openMembersModal, updateMember, removeMember, addMember,

      // Internal drag & drop
      dragItem, dropTargetId,
      onDragStartItem, onDragEndItem, onDragOverFolder, onDragLeaveFolder, onDropOnFolder,
    };
  },
});
</script>
