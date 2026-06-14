const axios = require('axios'); 

const headersScanner = (headers = {}) => {
  const clean = {};
  Object.keys(headers).forEach(k => clean[k.toLowerCase()] = headers[k]);
  return {
    csp: !!clean["content-security-policy"],
    hsts: !!clean["strict-transport-security"],
    xFrame: !!clean["x-frame-options"],
    xContent: !!clean["x-content-type-options"],
    referrer: !!clean["referrer-policy"]
  };
};

const cookieScanner = (cookies = []) => {
  return {
    secure: cookies.some(c => c.secure === true),
    httpOnly: cookies.some(c => c.httpOnly === true),
    sameSite: cookies.some(c => c.sameSite && c.sameSite !== 'None')
  };
};

const scoreCalculator = (ssl, headers, cookies, exposedFilesCount) => {
  let score = 0;
  if (ssl.valid) score += 25;
  if (headers.csp) score += 15;
  if (headers.hsts) score += 15;
  if (headers.xFrame) score += 10;
  if (headers.xContent) score += 10;
  if (headers.referrer) score += 10;
  if (cookies.secure) score += 5;
  if (cookies.httpOnly) score += 5;
  if (cookies.sameSite) score += 5;

  score -= (exposedFilesCount * 20);
  
  return Math.max(0, score); 
};

const axios = require('axios');

const checkSensitiveFiles = async (baseUrl) => {
  const filesToTest = [
    { name: "Fichier d'environnement (.env)", path: '/.env', keywords: ['DB_', 'SECRET', 'APP_ENV', 'AWS_'] },
    { name: "Fichier d'environnement local (.env.local)", path: '/.env.local', keywords: ['DB_', 'SECRET'] },
    { name: "Fichier d'environnement de production (.env.production)", path: '/.env.production', keywords: ['DB_', 'SECRET'] },
    { name: "Exemple d'environnement (.env.example)", path: '/.env.example', keywords: ['DB_', 'SECRET'] },
    { name: 'Dossier Git Interne (.git/HEAD)', path: '/.git/HEAD', keywords: ['ref: refs/'] },
    { name: 'Configuration Git (.git/config)', path: '/.git/config', keywords: ['[core]', '[remote'] },
    { name: 'Fichier d\'index Git (.git/index)', path: '/.git/index' }, 
    { name: 'Dossier Subversion (.svn/entries)', path: '/.svn/entries' },
    { name: 'Configuration WordPress (wp-config.php)', path: '/wp-config.php', keywords: ['DB_PASSWORD', 'wp-settings.php'] },
    { name: 'Configuration de build WordPress (wp-config.txt)', path: '/wp-config.txt', keywords: ['DB_PASSWORD'] },
    { name: 'Configuration Nginx (nginx.conf)', path: '/nginx.conf', keywords: ['server {', 'listen '] },
    { name: 'Configuration Apache (.htaccess)', path: '/.htaccess', keywords: ['RewriteEngine', 'AuthType'] },
    { name: 'Archive du site web (backup.zip)', path: '/backup.zip' },
    { name: 'Archive du site web (site.zip)', path: '/site.zip' },
    { name: 'Archive de code source (src.zip)', path: '/src.zip' },
    { name: 'Fichier de configuration de secours (config.bak)', path: '/config.bak' },
    { name: 'Fichier de base de données de secours (backup.sql)', path: '/backup.sql', keywords: ['INSERT INTO', 'CREATE TABLE'] },
    { name: 'Base de données SQL (db.sql)', path: '/db.sql', keywords: ['INSERT INTO', 'CREATE TABLE'] },
    { name: 'Base de données SQLite (database.sqlite)', path: '/database.sqlite' },
    { name: 'Base de données SQLite standard (db.sqlite)', path: '/db.sqlite' },
    { name: 'Fichier de Logs d\'erreurs (error_log)', path: '/error_log', keywords: ['PHP Fatal error', 'Stack trace'] },
    { name: 'Logs d\'erreurs PHP (php_errors.log)', path: '/php_errors.log', keywords: ['PHP Warning', 'PHP Notice'] },
    { name: 'Clé SSH Privée (id_rsa)', path: '/.ssh/id_rsa', keywords: ['-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----'] },
    { name: 'Configuration Docker Compose (docker-compose.yml)', path: '/docker-compose.yml', keywords: ['version:', 'services:', 'image:'] },
    { name: 'Configuration de déploiement (deploy.sh)', path: '/deploy.sh', keywords: ['#!/bin/bash', '#!/bin/sh'] }
  ];

  let exposed = [];
  const cleanBaseUrl = baseUrl.replace(/\/$/, '');

  let soft404Content = null;
  try {
    const fakeUrl = `${cleanBaseUrl}/comportement-erreur-aleatoire-${Math.random().toString(36).substring(7)}.html`;
    const baselineRes = await axios.get(fakeUrl, { 
      timeout: 2000, 
      responseType: 'text',
      validateStatus: () => true 
    });
    
    if (baselineRes.status === 200) {
      soft404Content = typeof baselineRes.data === 'string' ? baselineRes.data : null;
    }
  } catch (e) {
  }

  for (const file of filesToTest) {
    try {
      const targetUrl = `${cleanBaseUrl}${file.path}`;
      
      const response = await axios.get(targetUrl, { 
        timeout: 2000, 
        responseType: 'text',
        validateStatus: (status) => status === 200 
      });

      const body = response.data;

      if (soft404Content && typeof body === 'string') {
        if (body.substring(0, 1000) === soft404Content.substring(0, 1000) || body === soft404Content) {
          continue; 
        }
      }

      if (typeof body === 'string' && (body.includes('window.location') || body.includes('http-equiv="refresh"'))) {
        continue;
      }

      if (file.keywords && typeof body === 'string') {
        const hasKeyword = file.keywords.some(keyword => {
          const inBody = body.includes(keyword);
          const inSoft404 = soft404Content ? soft404Content.includes(keyword) : false;
          return inBody && !inSoft404;
        });
        
        if (!hasKeyword) {
          continue; 
        }
      }

      exposed.push(file.name);

    } catch (err) {
    }
  }

  return exposed;
};

module.exports = { checkSensitiveFiles };


const scanWebsite = async (url) => {
  let browser;
  try {
    const { default: puppeteer } = await import('puppeteer');

    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    let mainResponseHeaders = {};
    page.on('response', (response) => {
      const rUrl = response.url().replace(/\/$/, "");
      const tUrl = url.replace(/\/$/, "");
      if (rUrl === tUrl || rUrl.startsWith(tUrl)) {
        mainResponseHeaders = response.headers();
      }
    });

    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 12000
    });

    if (Object.keys(mainResponseHeaders).length === 0 && response) {
      mainResponseHeaders = response.headers();
    }

    const finalUrl = page.url();
    const siteCookies = await page.cookies();
    
    await browser.close();
    browser = null;

    const exposedFiles = await checkSensitiveFiles(finalUrl);

    const ssl = { valid: finalUrl.startsWith("https"), protocol: finalUrl.startsWith("https") ? "HTTPS" : "HTTP" };
    const headerResult = headersScanner(mainResponseHeaders);
    const cookieResult = cookieScanner(siteCookies);
    
    const score = scoreCalculator(ssl, headerResult, cookieResult, exposedFiles.length);

    let findings = [];
    if (!ssl.valid) findings.push("Pas de chiffrement HTTPS");
    if (!headerResult.csp) findings.push("En-tête Content-Security-Policy (CSP) manquant");
    if (!headerResult.hsts) findings.push("En-tête Strict-Transport-Security (HSTS) manquant");

    if (exposedFiles.length > 0) {
      exposedFiles.forEach(file => {
        findings.push(`⚠️ SÉCURITÉ CRITIQUE : ${file} est accessible publiquement !`);
      });
    }

    return { 
      url: finalUrl, 
      score, 
      ssl, 
      headers: headerResult, 
      cookies: cookieResult, 
      exposedFiles, 
      findings, 
      createdAt: new Date() 
    };

  } catch (err) {
    console.error("📋 Erreur interceptée sur :", url, err.message);
    if (browser) await browser.close();

    return {
      url,
      score: 0,
      ssl: { valid: false, protocol: "BLOCKED/TIMEOUT" },
      headers: { csp: false, hsts: false, xFrame: false, xContent: false, referrer: false },
      cookies: { secure: false, httpOnly: false, sameSite: false },
      exposedFiles: [],
      findings: ["Le site a refusé la connexion ou a mis trop de temps à répondre (Anti-Bot)."],
      createdAt: new Date()
    };
  }
};

module.exports = { scanWebsite };