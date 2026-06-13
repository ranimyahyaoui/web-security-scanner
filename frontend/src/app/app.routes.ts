import { Routes } from '@angular/router';
import { Dashboard } from './pages/dashboard/dashboard';
import { Scan } from './pages/scan/scan';
import { History } from './pages/history/history';
import { LoginComponent } from './pages/login/login';
import { authGuard } from './guards/auth-guard';

export const routes: Routes = [
  { path: 'dashboard', canActivate: [authGuard], component: Dashboard  },
  { path: 'scan',canActivate: [authGuard], component: Scan },
  { path: 'history',canActivate: [authGuard] ,component: History },
  { path: 'login', component: LoginComponent },
  { path: '', redirectTo: 'login', pathMatch: 'full' }
];