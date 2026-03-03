import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, tap } from 'rxjs';
import { IUser } from '../models/user';
import { environment } from '../../../environments/environment';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private apiUrl = environment.apiUrl;
  http = inject(HttpClient);

  private currentUserSubject = new BehaviorSubject<IUser | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  get currentUserValue(): IUser | null {
    return this.currentUserSubject.getValue();
  }

  getCurrentUser(): Observable<IUser> {
    return this.http
      .get<IUser>(`${this.apiUrl}/auth/user/`)
      .pipe(tap(user => this.currentUserSubject.next(user)));
  }
}
