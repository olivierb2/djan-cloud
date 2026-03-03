import {
  Component,
  inject,
  OnInit,
  OnDestroy,
  Output,
  EventEmitter,
} from '@angular/core';
import { Router, RouterLink, RouterLinkActive } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RoutePaths } from '../../constants/routes';
import { IUser } from '../../models/user';
import { Subscription } from 'rxjs';
import { UserService } from '../../services/user.service';
import { FileService, TreeNode, TreeResponse } from '../../services/file.service';
import { SharedFolderService } from '../../services/shared-folder.service';
import { AdminService, AdminUser } from '../../services/admin.service';
import { NgIcon } from '@ng-icons/core';

@Component({
  selector: 'app-sidebar',
  imports: [RouterLink, RouterLinkActive, CommonModule, FormsModule, NgIcon],
  templateUrl: './sidebar.html',
  styleUrl: './sidebar.scss',
})
export class Sidebar implements OnInit, OnDestroy {
  public router = inject(Router);
  private userService = inject(UserService);
  private fileService = inject(FileService);
  private sharedFolderService = inject(SharedFolderService);
  private adminService = inject(AdminService);

  private subscriptions: Subscription[] = [];
  currentUser: IUser | null = null;
  isCollapsed = false;
  tree: TreeNode | null = null;
  sharedFolders: TreeNode[] = [];
  isAdmin = false;
  expandedFolders = new Set<number>();
  activeBrowsePath = '';

  showCreateSharedModal = false;
  newSharedFolderName = '';

  // Members modal
  showMembersModal = false;
  membersSharedFolderId = 0;
  members: { user_id: number; email: string; permission: string }[] = [];
  allUsers: AdminUser[] = [];
  addMemberUserId: number | null = null;
  addMemberPermission = 'read';

  @Output() collapsedChange = new EventEmitter<boolean>();

  protected readonly RoutePaths = RoutePaths;

  ngOnInit(): void {
    const savedState = localStorage.getItem('sidebar-collapsed');
    if (savedState !== null) {
      this.isCollapsed = JSON.parse(savedState);
      this.collapsedChange.emit(this.isCollapsed);
    }

    this.subscriptions.push(
      this.userService.currentUser$.subscribe(user => {
        this.currentUser = user;
        if (user) {
          this.isAdmin = user.is_admin;
        }
      }),
      this.fileService.treeChanged.subscribe(() => this.loadTree()),
      this.fileService.activeBrowsePath.subscribe(path => {
        this.activeBrowsePath = path;
        this.expandActivePath();
      }),
    );

    this.loadTree();
  }

  loadTree(): void {
    this.fileService.getTree().subscribe({
      next: (res: TreeResponse) => {
        this.tree = res.tree;
        this.sharedFolders = res.shared;
        this.isAdmin = res.is_admin;
        this.expandActivePath();
      },
    });
  }

  private expandActivePath(): void {
    if (!this.activeBrowsePath) return;
    if (this.tree) {
      this.expandMatchingNodes(this.tree.children, this.activeBrowsePath);
    }
    for (const sf of this.sharedFolders) {
      this.expandMatchingNodes(sf.children, this.activeBrowsePath);
    }
  }

  private expandMatchingNodes(nodes: TreeNode[], currentPath: string): boolean {
    for (const node of nodes) {
      if (currentPath === node.url_path || currentPath.startsWith(node.url_path + '/')) {
        this.expandedFolders.add(node.id);
        if (node.children.length > 0) {
          this.expandMatchingNodes(node.children, currentPath);
        }
        return true;
      }
    }
    return false;
  }

  toggleSidebar(): void {
    this.isCollapsed = !this.isCollapsed;
    localStorage.setItem('sidebar-collapsed', JSON.stringify(this.isCollapsed));
    this.collapsedChange.emit(this.isCollapsed);
  }

  toggleFolder(folderId: number, event: Event): void {
    event.preventDefault();
    event.stopPropagation();
    if (this.expandedFolders.has(folderId)) {
      this.expandedFolders.delete(folderId);
    } else {
      this.expandedFolders.add(folderId);
    }
  }

  isFolderExpanded(folderId: number): boolean {
    return this.expandedFolders.has(folderId);
  }

  isMyFilesActive(): boolean {
    return !this.activeBrowsePath.startsWith('__shared__');
  }

  openCreateSharedModal(event: Event): void {
    event.preventDefault();
    event.stopPropagation();
    this.newSharedFolderName = '';
    this.showCreateSharedModal = true;
  }

  createSharedFolder(): void {
    if (!this.newSharedFolderName.trim()) return;
    this.sharedFolderService.create(this.newSharedFolderName).subscribe({
      next: () => {
        this.showCreateSharedModal = false;
        this.loadTree();
      },
    });
  }

  openMembersModal(sfId: number, event: Event): void {
    event.preventDefault();
    event.stopPropagation();
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

  ngOnDestroy(): void {
    this.subscriptions.forEach(s => s.unsubscribe());
  }
}
