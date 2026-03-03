import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class SharedFolderService {
  private http = inject(HttpClient);
  private apiUrl = environment.apiUrl;

  create(name: string): Observable<{ id: number; name: string }> {
    return this.http.post<{ id: number; name: string }>(
      `${this.apiUrl}/shared-folders/create/`,
      { name }
    );
  }

  getMembers(sfId: number): Observable<{ members: { user_id: number; email: string; permission: string }[] }> {
    return this.http.get<any>(`${this.apiUrl}/shared-folders/${sfId}/members/`);
  }

  addMember(sfId: number, userId: number, permission: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/shared-folders/${sfId}/members/`, { user_id: userId, permission });
  }

  removeMember(sfId: number, userId: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/shared-folders/${sfId}/members/${userId}/`);
  }
}
