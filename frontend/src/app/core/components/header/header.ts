import { Component, inject, signal, OnInit, OnDestroy } from '@angular/core';
import { Router, NavigationEnd } from '@angular/router';
import { RoutePaths } from '../../constants/routes';
import { filter, Subject, takeUntil } from 'rxjs';
import { UserService } from '../../services/user.service';
import { Auth } from '../../services/auth';
import { IUser } from '../../models/user';
import { NgIcon } from '@ng-icons/core';

@Component({
  selector: 'app-header',
  imports: [NgIcon],
  templateUrl: './header.html',
  styleUrl: './header.scss',
})
export class Header implements OnInit, OnDestroy {
  protected router = inject(Router);
  private userService = inject(UserService);
  private authService = inject(Auth);
  private destroy$ = new Subject<void>();

  showProfileMenu = signal(false);
  pageTitle = signal('Files');
  currentUser: IUser | null = null;

  protected readonly RoutePaths = RoutePaths;

  ngOnInit() {
    this.userService.currentUser$
      .pipe(takeUntil(this.destroy$))
      .subscribe(user => {
        this.currentUser = user;
      });

    this.router.events
      .pipe(
        filter(event => event instanceof NavigationEnd),
        takeUntil(this.destroy$)
      )
      .subscribe(() => this.updatePageInfo());
    this.updatePageInfo();
  }

  ngOnDestroy() {
    this.destroy$.next();
    this.destroy$.complete();
  }

  private updatePageInfo() {
    const url = this.router.url;
    if (url.includes('/users')) {
      this.pageTitle.set('Users');
    } else {
      this.pageTitle.set('Files');
    }
  }

  getUserDisplayName(): string {
    if (!this.currentUser) return '';
    return this.currentUser.email;
  }

  getUserInitials(): string {
    if (!this.currentUser) return '';
    return this.currentUser.email.substring(0, 2).toUpperCase();
  }

  toggleProfileMenu() {
    this.showProfileMenu.update(v => !v);
  }

  closeProfileMenu() {
    this.showProfileMenu.set(false);
  }

  onLogout() {
    this.closeProfileMenu();
    this.authService.removeToken();
    this.router.navigate(['/', RoutePaths.AUTH]);
  }
}
