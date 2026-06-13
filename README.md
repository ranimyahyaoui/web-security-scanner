# Web Security Scanner

## Overview

Web Security Scanner is a full-stack web application designed to analyze the security posture of websites. The application performs automated checks on SSL/TLS usage, HTTP security headers, and cookie configurations, then generates a security score and a detailed report.

## Features

* User authentication with JWT
* User registration and login
* Website security scanning
* SSL/HTTPS verification
* HTTP security headers analysis
* Cookie security analysis
* Security score calculation
* Scan history management
* Interactive dashboard
* PDF report generation and export

## Technology Stack

### Frontend

* Angular
* TypeScript
* HTML/CSS

### Backend

* Node.js
* Express.js

### Database

* MongoDB
* Mongoose

### Security

* JWT Authentication
* Password hashing with bcrypt

## Security Checks

The scanner evaluates:

* HTTPS/SSL usage
* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Secure Cookies
* HttpOnly Cookies
* SameSite Cookies

## Project Structure

web-security-scanner/

* frontend/
* backend/
* controllers/
* routes/
* models/
* services/
* middleware/

## Future Improvements

* Advanced OWASP vulnerability detection
* Real-time monitoring
* Security analytics charts
* AI-powered recommendations
* Public deployment

## Author

Ranim Yahyaoui

Cybersecurity & Software Engineering Student
