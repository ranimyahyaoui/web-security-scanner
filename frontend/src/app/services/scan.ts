import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ScanService {
  private apiUrl: string = 'http://localhost:3000/api/scans'; 

  constructor(private http: HttpClient) {}

  scanWebsite(url: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/run`, { url });
  }

  getHistory(): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/history`); 
  }
  downloadRapportPdf(scanId: string): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/export-pdf/${scanId}`, {
      responseType: 'blob' 
    });
  }
}