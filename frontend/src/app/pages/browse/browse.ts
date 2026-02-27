import { Component, inject, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subject, takeUntil, switchMap } from 'rxjs';
import { FileService, BrowseResponse } from '../../core/services/file.service';
import { SharedFolderService } from '../../core/services/shared-folder.service';
import { AdminService, AdminUser } from '../../core/services/admin.service';
import { RoutePaths } from '../../core/constants/routes';
import { NgIcon } from '@ng-icons/core';

@Component({
  selector: 'app-browse',
  imports: [CommonModule, FormsModule, RouterLink, NgIcon],
  templateUrl: './browse.html',
  styleUrl: './browse.scss',
})
export class BrowsePage implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private fileService = inject(FileService);
  private sharedFolderService = inject(SharedFolderService);
  private adminService = inject(AdminService);
  private destroy$ = new Subject<void>();

  data: BrowseResponse | null = null;
  loading = true;
  currentPath = '';

  // Modals
  showNewFolderModal = false;
  showNewFileModal = false;
  showRenameModal = false;
  showMoveModal = false;
  showSharedFolderModal = false;
  showMembersModal = false;
  showPreviewModal = false;

  // Form fields
  newFolderName = '';
  newFileName = '';
  renameName = '';
  renameType = '';
  renameId = 0;
  sharedFolderName = '';
  previewContent = '';
  previewFileName = '';

  // Members modal
  membersSharedFolderId = 0;
  members: { user_id: number; email: string; permission: string }[] = [];
  allUsers: AdminUser[] = [];
  addMemberUserId: number | null = null;
  addMemberPermission = 'read';

  // Move modal
  moveType = '';
  moveId = 0;

  // Upload
  uploading = false;

  protected readonly RoutePaths = RoutePaths;

  ngOnInit(): void {
    this.route.params
      .pipe(
        takeUntil(this.destroy$),
        switchMap(params => {
          this.currentPath = params['path'] || '';
          this.loading = true;
          return this.fileService.browse(this.currentPath);
        })
      )
      .subscribe({
        next: data => {
          this.data = data;
          this.loading = false;
        },
        error: () => {
          this.loading = false;
        },
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  refresh(): void {
    this.loading = true;
    this.fileService.browse(this.currentPath).subscribe({
      next: data => {
        this.data = data;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      },
    });
  }

  navigateToFolder(urlPath: string): void {
    this.router.navigate(['/', RoutePaths.APP, RoutePaths.BROWSE, urlPath]);
  }

  navigateToParent(): void {
    if (this.data?.parent_path !== null && this.data?.parent_path !== undefined) {
      if (this.data.parent_path === '') {
        this.router.navigate(['/', RoutePaths.APP, RoutePaths.BROWSE]);
      } else {
        this.router.navigate(['/', RoutePaths.APP, RoutePaths.BROWSE, this.data.parent_path]);
      }
    }
  }

  // Upload
  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (!input.files?.length) return;
    this.uploading = true;
    const file = input.files[0];
    this.fileService.uploadFile(this.currentPath, file).subscribe({
      next: () => {
        this.uploading = false;
        this.refresh();
        input.value = '';
      },
      error: () => {
        this.uploading = false;
        input.value = '';
      },
    });
  }

  // New folder
  openNewFolderModal(): void {
    this.newFolderName = '';
    this.showNewFolderModal = true;
  }

  createFolder(): void {
    if (!this.newFolderName.trim()) return;
    this.fileService.createFolder(this.currentPath, this.newFolderName).subscribe({
      next: () => {
        this.showNewFolderModal = false;
        this.refresh();
        this.fileService.notifyTreeChanged();
      },
    });
  }

  // New file
  openNewFileModal(): void {
    this.newFileName = '';
    this.showNewFileModal = true;
  }

  createFile(): void {
    if (!this.newFileName.trim()) return;
    this.fileService.createFile(this.currentPath, this.newFileName).subscribe({
      next: () => {
        this.showNewFileModal = false;
        this.refresh();
      },
    });
  }

  // Rename
  openRenameModal(type: string, id: number, currentName: string): void {
    this.renameType = type;
    this.renameId = id;
    this.renameName = currentName;
    this.showRenameModal = true;
  }

  renameItem(): void {
    if (!this.renameName.trim()) return;
    this.fileService.renameItem(this.renameType, this.renameId, this.renameName).subscribe({
      next: () => {
        this.showRenameModal = false;
        this.refresh();
        this.fileService.notifyTreeChanged();
      },
    });
  }

  // Delete
  deleteFile(id: number): void {
    if (!confirm('Delete this file?')) return;
    this.fileService.deleteFile(id).subscribe({ next: () => this.refresh() });
  }

  deleteFolder(id: number): void {
    if (!confirm('Delete this folder and all its contents?')) return;
    this.fileService.deleteFolder(id).subscribe({ next: () => { this.refresh(); this.fileService.notifyTreeChanged(); } });
  }

  // Download
  downloadFile(id: number, fileName?: string): void {
    this.fileService.downloadFile(id).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName || 'download';
        a.click();
        URL.revokeObjectURL(url);
      },
    });
  }

  // Preview
  openPreview(id: number): void {
    this.fileService.getPreview(id).subscribe({
      next: res => {
        if (res.type === 'text') {
          this.previewFileName = res.display_name;
          this.previewContent = res.content || '';
          this.showPreviewModal = true;
        } else {
          this.downloadFile(id);
        }
      },
    });
  }

  // Shared folder
  openSharedFolderModal(): void {
    this.sharedFolderName = '';
    this.showSharedFolderModal = true;
  }

  createSharedFolder(): void {
    if (!this.sharedFolderName.trim()) return;
    this.sharedFolderService.create(this.sharedFolderName).subscribe({
      next: () => {
        this.showSharedFolderModal = false;
        this.refresh();
        this.fileService.notifyTreeChanged();
      },
    });
  }

  // Members
  openMembersModal(sfId: number): void {
    this.membersSharedFolderId = sfId;
    this.addMemberUserId = null;
    this.addMemberPermission = 'read';
    this.sharedFolderService.getMembers(sfId).subscribe({
      next: res => {
        this.members = res.members;
        this.showMembersModal = true;
        this.adminService.getUsers().subscribe({
          next: usersRes => {
            this.allUsers = usersRes.users;
          },
        });
      },
    });
  }

  get availableUsers(): AdminUser[] {
    const memberIds = new Set(this.members.map(m => m.user_id));
    return this.allUsers.filter(u => !memberIds.has(u.id));
  }

  addMember(): void {
    if (!this.addMemberUserId) return;
    this.sharedFolderService.addMember(this.membersSharedFolderId, this.addMemberUserId, this.addMemberPermission).subscribe({
      next: res => {
        this.members.push({ user_id: res.user_id, email: res.email, permission: res.permission });
        this.addMemberUserId = null;
        this.addMemberPermission = 'read';
      },
    });
  }

  updateMemberPermission(userId: number, permission: string): void {
    this.sharedFolderService.addMember(this.membersSharedFolderId, userId, permission).subscribe({
      next: res => {
        const member = this.members.find(m => m.user_id === userId);
        if (member) member.permission = res.permission;
      },
    });
  }

  removeMember(userId: number): void {
    this.sharedFolderService.removeMember(this.membersSharedFolderId, userId).subscribe({
      next: () => {
        this.members = this.members.filter(m => m.user_id !== userId);
      },
    });
  }

  closeAllModals(): void {
    this.showNewFolderModal = false;
    this.showNewFileModal = false;
    this.showRenameModal = false;
    this.showMoveModal = false;
    this.showSharedFolderModal = false;
    this.showMembersModal = false;
    this.showPreviewModal = false;
  }

  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  getFileIcon(contentType: string): string {
    if (contentType.startsWith('image/')) return 'heroDocumentText';
    if (contentType.startsWith('text/')) return 'heroDocumentText';
    return 'heroDocumentText';
  }
}
