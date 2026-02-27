import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AdminService, AdminUser } from '../../core/services/admin.service';
import { NgIcon } from '@ng-icons/core';

@Component({
  selector: 'app-users',
  imports: [CommonModule, FormsModule, NgIcon],
  templateUrl: './users.html',
  styleUrl: './users.scss',
})
export class UsersPage implements OnInit {
  private adminService = inject(AdminService);

  users: AdminUser[] = [];
  loading = true;
  showCreateModal = false;

  newEmail = '';
  newPassword = '';
  newRole = 'user';
  creating = false;

  ngOnInit(): void {
    this.loadUsers();
  }

  loadUsers(): void {
    this.loading = true;
    this.adminService.getUsers().subscribe({
      next: res => {
        this.users = res.users;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      },
    });
  }

  openCreateModal(): void {
    this.newEmail = '';
    this.newPassword = '';
    this.newRole = 'user';
    this.showCreateModal = true;
  }

  createUser(): void {
    if (!this.newEmail.trim() || !this.newPassword.trim()) return;
    this.creating = true;
    this.adminService
      .createUser({
        email: this.newEmail,
        password: this.newPassword,
        role: this.newRole,
      })
      .subscribe({
        next: () => {
          this.creating = false;
          this.showCreateModal = false;
          this.loadUsers();
        },
        error: () => {
          this.creating = false;
        },
      });
  }

  deleteUser(user: AdminUser): void {
    if (!confirm(`Delete user "${user.email}"?`)) return;
    this.adminService.deleteUser(user.id).subscribe({
      next: () => this.loadUsers(),
    });
  }
}
