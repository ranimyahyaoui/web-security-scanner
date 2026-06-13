import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://web-security-scanner-api.onrender.com/api/auth';

  constructor(private http: HttpClient) {}

  register(userData: any): Observable<string> {
    return this.http.post(`${this.apiUrl}/register`, userData, { responseType: 'text' });
  }

  login(credentials: any): Observable<string> {
    return this.http.post(`${this.apiUrl}/login`, credentials, { responseType: 'text' });
  }

  saveToken(token: string): void {
    localStorage.setItem('token', token);
  }

  saveUser(user: any): void {
    localStorage.setItem('user', JSON.stringify(user));
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  getUser(): any {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  }
isLoggedIn(): boolean {

  return !!localStorage.getItem('token'); 
}
}