import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService } from '../../services/scan';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.html',
  styleUrls: ['./dashboard.css']
})
export class Dashboard implements OnInit {
  
  totalScans: number = 0;
  averageScore: number = 0;
  recentScans: any[] = [];
  dangerousSites: any[] = [];
  
  secureCount: number = 0;
  warningCount: number = 0;
  dangerCount: number = 0;

  constructor(
    private scanService: ScanService, 
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadDashboardData();
  }
  loadDashboardData() {
    this.scanService.getHistory().subscribe({
      next: (res: any) => {       
        const scans = res as any[]; 
        if (!scans || scans.length === 0) return;
        
        this.totalScans = scans.length;
        const sum = scans.reduce((acc, scan) => acc + (scan.score || 0), 0);
        this.averageScore = Math.round(sum / this.totalScans);
        this.recentScans = scans.slice(0, 4);
        this.dangerousSites = scans.filter(scan => scan.score < 40).slice(0, 4);
        this.secureCount = scans.filter(scan => scan.score >= 75).length;
        this.warningCount = scans.filter(scan => scan.score >= 40 && scan.score < 75).length;
        this.dangerCount = scans.filter(scan => scan.score < 40).length;

        this.cdr.detectChanges();
      },
      error: (err: any) => console.error("Erreur lors du chargement du dashboard", err)
    });
  }

  getPercentage(count: number): number {
    if (this.totalScans === 0) return 0;
    return Math.round((count / this.totalScans) * 100);
  }

  getColorClass(score: number): string {
    if (score >= 75) return 'success';
    if (score >= 40) return 'warning';
    return 'danger';
  }
}