import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { Auth } from './pages/auth/auth';
import { Login } from './components/login/login';

const routes: Routes = [
  {
    path: '',
    component: Auth,
    children: [
      {
        path: '',
        pathMatch: 'full',
        component: Login,
      },
      {
        path: '**',
        redirectTo: '',
      },
    ],
  },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AuthRoutingModule { }
