import { Component, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScanService } from '../../services/scan';

@Component({
  selector: 'app-scan',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scan.html',
  styleUrls: ['./scan.css']
})
export class Scan {
  url: string = '';
  result: any = null;
  loading: boolean = false;
  errorMessage: string = '';

  constructor(
    private scanService: ScanService, 
    private cdr: ChangeDetectorRef
  ) {}

  launchScan() {
    this.errorMessage = '';
    this.result = null;

    if (!this.url) {
      this.errorMessage = "Veuillez entrer une URL.";
      return;
    }

    if (!/^https?:\/\//i.test(this.url)) {
      this.url = 'https://' + this.url;
    }

    this.loading = true;
    this.cdr.detectChanges();

    this.scanService.scanWebsite(this.url).subscribe({
      next: (res: any) => {
        this.result = res;
        this.loading = false;
        this.cdr.detectChanges(); 
      },
      error: (err: any) => {
        this.loading = false;
        if (err.status === 0) {
          this.errorMessage = "Impossible de joindre le serveur. Vérifie que ton Backend fonctionne !";
        } else {
          this.errorMessage = err.error?.message || "Le scan a échoué.";
        }
        this.cdr.detectChanges(); 
      }
    });
  }

  getColor(score: number): string {
    if (score >= 75) return 'success';
    if (score >= 40) return 'warning';
    return 'danger';
  }
  downloadPDF(scanId: string) {
  if (!scanId) return;

  this.scanService.downloadRapportPdf(scanId).subscribe({
    next: (blob: Blob) => {
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `Rapport_Securite_${scanId}.pdf`;
      link.click(); 
      window.URL.revokeObjectURL(url); 
    },
    error: (err) => console.error("Échec du téléchargement du PDF", err)
  });
}
}