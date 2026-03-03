import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface AdminUser {
  id: number;
  email: string;
  role: string;
  is_active: boolean;
}

@Injectable({ providedIn: 'root' })
export class AdminService {
  private http = inject(HttpClient);
  private apiUrl = environment.apiUrl;

  getUsers(): Observable<{ users: AdminUser[] }> {
    return this.http.get<{ users: AdminUser[] }>(`${this.apiUrl}/users/`);
  }

  createUser(data: { email: string; password: string; role: string }): Observable<AdminUser> {
    return this.http.post<AdminUser>(`${this.apiUrl}/users/create/`, data);
  }

  deleteUser(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/users/${id}/`);
  }
}
