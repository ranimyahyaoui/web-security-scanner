import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormGroup, FormControl, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth';
import { Router, RouterLink } from '@angular/router';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule,RouterLink],
  templateUrl: './login.html'
})
export class LoginComponent {
  errorMessage = '';

  loginForm = new FormGroup({
    email: new FormControl('', [Validators.required, Validators.email]),
    password: new FormControl('', [Validators.required])
  });

  constructor(private authService: AuthService, private router: Router) {}


send() {
  if (this.loginForm.invalid) return;

  const credentials = this.loginForm.value;

  this.authService.login(credentials).subscribe({
    next: (response: string) => {
      try {
        const data = JSON.parse(response);
        
        if (data && data.token) {
          this.authService.saveToken(data.token); 
          this.authService.saveUser(data.user);  
          
          this.router.navigate(['/dashboard']);
        } else {
          this.errorMessage = "Format de réponse du serveur invalide.";
        }
      } catch (e) {
        this.errorMessage = "Erreur lors du traitement des données de connexion.";
        console.error(e);
      }
    },
    error: (httpError) => {
      console.log('Erreur brute reçue du serveur :', httpError.error);
      try {
        const parsedError = JSON.parse(httpError.error);
        this.errorMessage = parsedError.message || "Identifiants incorrects.";
      } catch (e) {
        this.errorMessage = typeof httpError.error === 'string' ? httpError.error : "Une erreur technique est survenue.";
      }
    }
  });
}
}