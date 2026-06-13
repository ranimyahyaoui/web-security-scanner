import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../services/auth';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './register.html'
})
export class RegisterComponent {
  userData = { email: '', password: '' };
  message = '';
  isSuccess = false;

  constructor(private authService: AuthService, private router: Router) {}

  onSubmit() {
    this.authService.register(this.userData).subscribe({
      next: (response) => {
        this.isSuccess = true;
        this.message = "Inscription réussie ! Redirection vers la page de connexion...";
        setTimeout(() => this.router.navigate(['/login']), 2000);
      },
      error: (err) => {
        this.isSuccess = false;
        this.message = "Erreur lors de l'inscription. L'utilisateur existe peut-être déjà.";
        console.error(err);
      }
    });
  }
}