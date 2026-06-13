import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard/dashboard';
import { Scan } from './pages/scan/scan';
import { History } from './pages/history/history';
import { LoginComponent } from './pages/login/login';
import { authGuard } from './guards/auth-guard';
import { NotFound } from './pages/not-found/not-found';
import { RegisterComponent } from './pages/register/register';

export const routes: Routes = [
  { path: 'dashboard', canActivate: [authGuard], component: Dashboard  },
  { path: 'scan',canActivate: [authGuard], component: Scan },
  { path: 'history',canActivate: [authGuard] ,component: History },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },

  { path: '', redirectTo: 'register', pathMatch: 'full' },
  { path: '**', component: NotFound }
];