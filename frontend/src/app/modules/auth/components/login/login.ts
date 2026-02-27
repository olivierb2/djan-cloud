import { Component, inject } from '@angular/core';
import { Router } from '@angular/router';
import { FormGroup, Validators, FormBuilder, FormControl, ReactiveFormsModule } from '@angular/forms';
import { Auth } from '../../../../core/services/auth';
import { RoutePaths } from '../../../../core/constants/routes';
import { CommonModule } from '@angular/common';

interface LoginForm {
  email: FormControl<string>;
  password: FormControl<string>;
}

@Component({
  selector: 'app-login',
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './login.html',
  styleUrl: './login.scss',
})
export class Login {
  errorMessage = '';
  loading = false;
  private router = inject(Router);
  private fb = inject(FormBuilder);
  private auth = inject(Auth);

  form: FormGroup<LoginForm> = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required]],
  });

  constructor() {
    this.form.valueChanges.subscribe(() => {
      this.errorMessage = '';
    });
  }

  onSubmit() {
    if (!this.form.valid) return;

    this.loading = true;
    const { email, password } = this.form.getRawValue();

    this.auth.login({ email, password }).subscribe({
      next: res => {
        this.auth.setToken(res.access);
        this.auth.setRefreshToken(res.refresh);
        this.loading = false;
        this.router.navigate([`/${RoutePaths.APP}`]);
      },
      error: err => {
        this.loading = false;
        this.errorMessage = err.error?.error || 'Login failed';
      },
    });
  }
}
