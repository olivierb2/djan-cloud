import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { IBodyLogin, IResponseLogin } from '../models/admin-auth';

@Injectable({
  providedIn: 'root',
})
export class Auth {
  http = inject(HttpClient);
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(this.isLoggedIn());
  public isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  isLoggedIn(): boolean {
    return !!localStorage.getItem('token');
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  setToken(token: string): void {
    localStorage.setItem('token', token);
    this.isAuthenticatedSubject.next(true);
  }

  getRefreshToken(): string | null {
    return localStorage.getItem('refreshToken');
  }

  setRefreshToken(token: string): void {
    localStorage.setItem('refreshToken', token);
  }

  removeToken(): void {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    this.isAuthenticatedSubject.next(false);
  }

  refreshAccessToken(): Observable<{ access: string }> {
    const refresh = this.getRefreshToken();
    return this.http.post<{ access: string }>(
      `${environment.apiUrl}/auth/token/refresh/`,
      { refresh }
    );
  }

  login(body: IBodyLogin): Observable<IResponseLogin> {
    return this.http.post<IResponseLogin>(
      `${environment.apiUrl}/auth/login/`,
      body
    );
  }
}
