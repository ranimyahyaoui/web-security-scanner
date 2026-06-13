import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService } from '../../services/scan';

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './history.html',
  styleUrls: ['./history.css']
})
export class History implements OnInit {
  history: any[] = [];
  selectedScan: any = null; // Stocke le scan sur lequel l'utilisateur a cliqué

  constructor(private scanService: ScanService, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.scanService.getHistory().subscribe({
      next: (res: any) => {
        this.history = res;
        this.cdr.detectChanges();
      },
      // 🔥 CORRECTION : Ajout du type ": any" sur le paramètre err
      error: (err: any) => console.error("Impossible de charger l'historique", err)
    });
  }

  // Activer la vue détaillée
  viewDetails(scan: any) {
    this.selectedScan = scan;
    this.cdr.detectChanges();
  }

  // Revenir à la liste
  closeDetails() {
    this.selectedScan = null;
    this.cdr.detectChanges();
  }

  getColor(score: number): string {
    if (score >= 75) return 'success';
    if (score >= 40) return 'warning';
    return 'danger';
  }
}