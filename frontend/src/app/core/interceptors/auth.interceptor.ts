import {
  HttpInterceptorFn,
  HttpRequest,
  HttpHandlerFn,
  HttpErrorResponse,
} from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Auth } from '../services/auth';

let isRefreshing = false;

function addAuthHeaders(
  req: HttpRequest<unknown>,
  token: string | null,
): HttpRequest<unknown> {
  if (token) {
    return req.clone({
      headers: req.headers.set('Authorization', `Bearer ${token}`),
    });
  }
  return req;
}

export const authInterceptor: HttpInterceptorFn = (
  req: HttpRequest<unknown>,
  next: HttpHandlerFn
) => {
  const router = inject(Router);
  const auth = inject(Auth);

  if (!req.url.startsWith(environment.apiUrl)) {
    return next(req);
  }

  const token = auth.getToken();
  const authReq = addAuthHeaders(req, token);

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      if (
        error.status === 401 &&
        error.error?.code === 'token_not_valid' &&
        !isRefreshing &&
        auth.getRefreshToken() &&
        !req.url.includes('/auth/token/refresh/')
      ) {
        isRefreshing = true;
        return auth.refreshAccessToken().pipe(
          switchMap(response => {
            isRefreshing = false;
            auth.setToken(response.access);
            const retryReq = addAuthHeaders(req, response.access);
            return next(retryReq);
          }),
          catchError(refreshError => {
            isRefreshing = false;
            auth.removeToken();
            router.navigate(['/auth']);
            return throwError(() => refreshError);
          })
        );
      }

      if (error.status === 401) {
        auth.removeToken();
        router.navigate(['/auth']);
      }

      return throwError(() => error);
    })
  );
};
