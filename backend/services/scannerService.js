const puppeteer = require('puppeteer');
const axios = require('axios'); // Ajout indispensable pour le scan rapide en arrière-plan

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

  // Applique une pénalité sévère : -20 points par fichier sensible exposé
  score -= (exposedFilesCount * 20);
  
  return Math.max(0, score); // Empêche le score d'être négatif
};

const checkSensitiveFiles = async (baseUrl) => {
  const filesToTest = [
    // --- 1. ENVIRONNEMENT & CLÉS D'API ---
    { name: "Fichier d'environnement (.env)", path: '/.env' },
    { name: "Fichier d'environnement local (.env.local)", path: '/.env.local' },
    { name: "Fichier d'environnement de production (.env.production)", path: '/.env.production' },
    { name: "Exemple d'environnement (.env.example)", path: '/.env.example' },

    // --- 2. GESTIONNAIRES DE VERSION (GIT & SVN) ---
    { name: 'Dossier Git Interne (.git/HEAD)', path: '/.git/HEAD' },
    { name: 'Configuration Git (.git/config)', path: '/.git/config' },
    { name: 'Fichier d\'index Git (.git/index)', path: '/.git/index' },
    { name: 'Dossier Subversion (.svn/entries)', path: '/.svn/entries' },

    // --- 3. CONFIGURATIONS DE SERVEURS & CMS ---
    { name: 'Configuration WordPress (wp-config.php)', path: '/wp-config.php' },
    { name: 'Configuration de build WordPress (wp-config.txt)', path: '/wp-config.txt' },
    { name: 'Configuration Nginx (nginx.conf)', path: '/nginx.conf' },
    { name: 'Configuration Apache (.htaccess)', path: '/.htaccess' },

    // --- 4. ARCHIVES, BACKUPS & SAUVEGARDES ---
    { name: 'Archive du site web (backup.zip)', path: '/backup.zip' },
    { name: 'Archive du site web (site.zip)', path: '/site.zip' },
    { name: 'Archive de code source (src.zip)', path: '/src.zip' },
    { name: 'Fichier de configuration de secours (config.bak)', path: '/config.bak' },
    { name: 'Fichier de base de données de secours (backup.sql)', path: '/backup.sql' },
    { name: 'Base de données SQL (db.sql)', path: '/db.sql' },

    // --- 5. BASES DE DONNÉES LOCALES FILE-BASED ---
    { name: 'Base de données SQLite (database.sqlite)', path: '/database.sqlite' },
    { name: 'Base de données SQLite standard (db.sqlite)', path: '/db.sqlite' },

    // --- 6. FICHIERS COMPORTANT DES LOGS ou DES CLÉS ---
    { name: 'Fichier de Logs d\'erreurs (error_log)', path: '/error_log' },
    { name: 'Logs d\'erreurs PHP (php_errors.log)', path: '/php_errors.log' },
    { name: 'Clé SSH Privée (id_rsa)', path: '/.ssh/id_rsa' },

    // --- 7. DOCKER & DÉPLOIEMENT ---
    { name: 'Configuration Docker Compose (docker-compose.yml)', path: '/docker-compose.yml' },
    { name: 'Configuration de déploiement (deploy.sh)', path: '/deploy.sh' }
  ];

  let exposed = [];
  
  for (const file of filesToTest) {
    try {
      const targetUrl = `${baseUrl.replace(/\/$/, '')}${file.path}`;
      
      const response = await axios.get(targetUrl, { 
        timeout: 2000, // Timeout rapide pour ne pas bloquer l'utilisateur
        validateStatus: (status) => status === 200 
      });

      if (response.status === 200) {
        exposed.push(file.name);
      }
    } catch (err) {
      // Les erreurs 404, 403, etc. signifient que le fichier est bien inaccessible.
    }
  }
  return exposed;
};

const scanWebsite = async (url) => {
  let browser;
  try {
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

    // 🚀 EXÉCUTION DU NOUVEAU SCAN DE FICHIERS SENSIBLES
    const exposedFiles = await checkSensitiveFiles(finalUrl);

    const ssl = { valid: finalUrl.startsWith("https"), protocol: finalUrl.startsWith("https") ? "HTTPS" : "HTTP" };
    const headerResult = headersScanner(mainResponseHeaders);
    const cookieResult = cookieScanner(siteCookies);
    
    // Calcul du score mis à jour avec les pénalités des fichiers exposés
    const score = scoreCalculator(ssl, headerResult, cookieResult, exposedFiles.length);

    let findings = [];
    if (!ssl.valid) findings.push("Pas de chiffrement HTTPS");
    if (!headerResult.csp) findings.push("En-tête Content-Security-Policy (CSP) manquant");
    if (!headerResult.hsts) findings.push("En-tête Strict-Transport-Security (HSTS) manquant");

    // Ajoute automatiquement les fichiers détectés à la liste des vulnérabilités
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
      exposedFiles, // Retourne aussi le tableau brut si Angular veut l'isoler
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