const axios = require('axios');


const headersScanner = (headers = {}) => {
  const clean = {};
  Object.keys(headers).forEach(k => (clean[k.toLowerCase()] = headers[k]));

  const cspValue = clean['content-security-policy'] || '';
  const cspPresent = !!cspValue;
  const cspStrict = cspPresent && !cspValue.includes("'unsafe-inline'") && !cspValue.includes('*');

  const hstsValue = clean['strict-transport-security'] || '';
  const hstsPresent = !!hstsValue;
  const hstsMaxAge = hstsPresent
    ? parseInt((hstsValue.match(/max-age=(\d+)/i) || [])[1] || '0', 10)
    : 0;
  const hstsStrict = hstsMaxAge >= 15552000; 

  const xFrameValue = clean['x-frame-options'] || '';
  const xFrame = !!xFrameValue;

  const xContentValue = clean['x-content-type-options'] || '';
  const xContent = xContentValue.toLowerCase() === 'nosniff';

  const referrerValue = clean['referrer-policy'] || '';
  const referrer = !!referrerValue;

  const permissionsPolicy = !!clean['permissions-policy'];

  const corp = !!clean['cross-origin-resource-policy'];
  const coep = !!clean['cross-origin-embedder-policy'];
  const coop = !!clean['cross-origin-opener-policy'];

  const serverValue = clean['server'] || '';
  const poweredBy = clean['x-powered-by'] || '';
  const versionLeaks = [];
  if (serverValue) versionLeaks.push({ header: 'Server', value: serverValue });
  if (poweredBy) versionLeaks.push({ header: 'X-Powered-By', value: poweredBy });

  return {
    csp: cspPresent,
    cspStrict,
    cspValue,
    hsts: hstsPresent,
    hstsStrict,
    hstsMaxAge,
    xFrame,
    xContent,
    referrer,
    permissionsPolicy,
    corp,
    coep,
    coop,
    versionLeaks,
  };
};

const cookieScanner = (cookies = []) => {
  const issues = [];

  cookies.forEach(c => {
    if (!c.secure) issues.push(`Cookie "${c.name}" sans flag Secure`);
    if (!c.httpOnly) issues.push(`Cookie "${c.name}" sans flag HttpOnly`);
    if (!c.sameSite || c.sameSite === 'None') {
      issues.push(`Cookie "${c.name}" sans SameSite strict/lax`);
    }
  });

  return {
    secure: cookies.length === 0 || cookies.every(c => c.secure),
    httpOnly: cookies.length === 0 || cookies.every(c => c.httpOnly),
    sameSite:
      cookies.length === 0 ||
      cookies.every(c => c.sameSite && c.sameSite !== 'None'),
    issues,
    total: cookies.length,
  };
};


const SCORE_WEIGHTS = {
  ssl: 20,
  cspPresent: 5,
  cspStrict: 10,
  hstsPresent: 5,
  hstsStrict: 10,
  xFrame: 8,
  xContent: 7,
  referrer: 5,
  permissionsPolicy: 5,
  corp: 3,
  coep: 3,
  coop: 3,
  cookiesSecure: 4,
  cookiesHttpOnly: 4,
  cookiesSameSite: 3,
};

const FILE_PENALTIES = {
  critical: 25, 
  high: 15,     
  medium: 8,   
  low: 4,       
};

const scoreCalculator = (ssl, headers, cookies, exposedFiles) => {
  let score = 0;

  if (ssl.valid) score += SCORE_WEIGHTS.ssl;
  if (headers.csp) score += SCORE_WEIGHTS.cspPresent;
  if (headers.cspStrict) score += SCORE_WEIGHTS.cspStrict;
  if (headers.hsts) score += SCORE_WEIGHTS.hstsPresent;
  if (headers.hstsStrict) score += SCORE_WEIGHTS.hstsStrict;
  if (headers.xFrame) score += SCORE_WEIGHTS.xFrame;
  if (headers.xContent) score += SCORE_WEIGHTS.xContent;
  if (headers.referrer) score += SCORE_WEIGHTS.referrer;
  if (headers.permissionsPolicy) score += SCORE_WEIGHTS.permissionsPolicy;
  if (headers.corp) score += SCORE_WEIGHTS.corp;
  if (headers.coep) score += SCORE_WEIGHTS.coep;
  if (headers.coop) score += SCORE_WEIGHTS.coop;
  if (cookies.secure) score += SCORE_WEIGHTS.cookiesSecure;
  if (cookies.httpOnly) score += SCORE_WEIGHTS.cookiesHttpOnly;
  if (cookies.sameSite) score += SCORE_WEIGHTS.cookiesSameSite;

  exposedFiles.forEach(f => {
    score -= FILE_PENALTIES[f.severity] || FILE_PENALTIES.medium;
  });

  score -= headers.versionLeaks.length * 3;

  return Math.max(0, Math.min(100, score));
};


const SENSITIVE_FILES = [
  { name: "Fichier d'environnement (.env)", path: '/.env', severity: 'critical' },
  { name: "Fichier d'environnement local (.env.local)", path: '/.env.local', severity: 'critical' },
  { name: "Fichier d'environnement de production (.env.production)", path: '/.env.production', severity: 'critical' },
  { name: 'Configuration Git interne (.git/config)', path: '/.git/config', severity: 'critical' },
  { name: 'HEAD Git (.git/HEAD)', path: '/.git/HEAD', severity: 'critical' },
  { name: 'Index Git (.git/index)', path: '/.git/index', severity: 'critical' },
  { name: 'Clé SSH Privée (id_rsa)', path: '/.ssh/id_rsa', severity: 'critical' },
  { name: 'Base de données SQL (db.sql)', path: '/db.sql', severity: 'critical' },
  { name: 'Sauvegarde SQL (backup.sql)', path: '/backup.sql', severity: 'critical' },
  { name: 'Base SQLite (database.sqlite)', path: '/database.sqlite', severity: 'critical' },
  { name: 'Base SQLite (db.sqlite)', path: '/db.sqlite', severity: 'critical' },
  { name: 'Configuration WordPress (wp-config.php)', path: '/wp-config.php', severity: 'high' },
  { name: 'Configuration WordPress texte (wp-config.txt)', path: '/wp-config.txt', severity: 'high' },
  { name: 'Docker Compose (docker-compose.yml)', path: '/docker-compose.yml', severity: 'high' },
  { name: 'Script de déploiement (deploy.sh)', path: '/deploy.sh', severity: 'high' },
  { name: 'Subversion (.svn/entries)', path: '/.svn/entries', severity: 'high' },
  { name: 'Configuration Nginx (nginx.conf)', path: '/nginx.conf', severity: 'medium' },
  { name: 'Configuration Apache (.htaccess)', path: '/.htaccess', severity: 'medium' },
  { name: 'Fichier de configuration de secours (config.bak)', path: '/config.bak', severity: 'medium' },
  { name: "Logs d'erreurs PHP (php_errors.log)", path: '/php_errors.log', severity: 'medium' },
  { name: "Logs d'erreurs (error_log)", path: '/error_log', severity: 'medium' },
  { name: "Exemple d'environnement (.env.example)", path: '/.env.example', severity: 'low' },
  { name: 'Archive de sauvegarde (backup.zip)', path: '/backup.zip', severity: 'low' },
  { name: 'Archive du site (site.zip)', path: '/site.zip', severity: 'low' },
  { name: 'Archive source (src.zip)', path: '/src.zip', severity: 'low' },
];

const CONTENT_SIGNATURES = {
  '/.env': ['=', 'KEY=', 'SECRET=', 'TOKEN=', 'DATABASE_URL'],
  '/.env.local': ['=', 'KEY=', 'SECRET='],
  '/.env.production': ['=', 'KEY=', 'SECRET='],
  '/.git/config': ['[core]', '[remote', 'repositoryformatversion'],
  '/.git/HEAD': ['ref:', 'refs/heads/'],
  '/wp-config.php': ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'table_prefix'],
  '/wp-config.txt': ['DB_NAME', 'DB_USER', 'DB_PASSWORD'],
  '/docker-compose.yml': ['version:', 'services:', 'image:'],
  '/nginx.conf': ['server {', 'listen ', 'location '],
  '/.htaccess': ['RewriteEngine', 'Options', 'Allow', 'Deny'],
  '/db.sql': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],
  '/backup.sql': ['CREATE TABLE', 'INSERT INTO'],
  '/.ssh/id_rsa': ['-----BEGIN', 'PRIVATE KEY'],
  '/deploy.sh': ['#!/bin/', 'ssh ', 'rsync '],
};


const isRealFileContent = (path, content, contentType) => {
  if (contentType && contentType.includes('text/html') && !path.endsWith('.php')) {
    return false;
  }

  const signatures = CONTENT_SIGNATURES[path];
  if (signatures) {
    return signatures.some(sig => content.includes(sig));
  }

  if (path.endsWith('.zip') || path.endsWith('.sqlite') || path.endsWith('.sql')) {
    return content.length > 0;
  }

  return true;
};

const checkSensitiveFiles = async (baseUrl) => {
  const exposed = [];
  const baseUrlClean = baseUrl.replace(/\/$/, '');

  const BATCH_SIZE = 5;
  for (let i = 0; i < SENSITIVE_FILES.length; i += BATCH_SIZE) {
    const batch = SENSITIVE_FILES.slice(i, i + BATCH_SIZE);

    const results = await Promise.allSettled(
      batch.map(async (file) => {
        const targetUrl = `${baseUrlClean}${file.path}`;
        try {
          const response = await axios.get(targetUrl, {
            timeout: 3000,
            validateStatus: (status) => status === 200,
            maxContentLength: 500 * 1024, 
            responseType: 'text',
            transformResponse: [(data) => data], 
          });

          if (response.status !== 200) return null;

          const contentType = response.headers['content-type'] || '';
          const content = typeof response.data === 'string' ? response.data : '';

          if (isRealFileContent(file.path, content, contentType)) {
            return { ...file, url: targetUrl };
          }
          return null;
        } catch {
          return null;
        }
      })
    );

    results.forEach((r) => {
      if (r.status === 'fulfilled' && r.value !== null) {
        exposed.push(r.value);
      }
    });
  }

  return exposed;
};


const buildFindings = (ssl, headers, cookies, exposedFiles) => {
  const findings = [];

  if (!ssl.valid) {
    findings.push({ severity: 'critical', message: 'Pas de chiffrement HTTPS — données transmises en clair' });
  }

  if (!headers.csp) {
    findings.push({ severity: 'high', message: 'Content-Security-Policy (CSP) manquant — risque XSS élevé' });
  } else if (!headers.cspStrict) {
    findings.push({ severity: 'medium', message: `CSP présent mais trop permissif (contient 'unsafe-inline' ou '*') : "${headers.cspValue}"` });
  }

  if (!headers.hsts) {
    findings.push({ severity: 'high', message: 'Strict-Transport-Security (HSTS) manquant' });
  } else if (!headers.hstsStrict) {
    findings.push({ severity: 'medium', message: `HSTS présent mais max-age trop court (${headers.hstsMaxAge}s < 15552000s)` });
  }

  if (!headers.xFrame) {
    findings.push({ severity: 'medium', message: 'X-Frame-Options manquant — risque de clickjacking' });
  }
  if (!headers.xContent) {
    findings.push({ severity: 'medium', message: 'X-Content-Type-Options manquant ou incorrect (doit être "nosniff")' });
  }
  if (!headers.referrer) {
    findings.push({ severity: 'low', message: 'Referrer-Policy manquant — fuite possible d\'URL en referer' });
  }
  if (!headers.permissionsPolicy) {
    findings.push({ severity: 'low', message: 'Permissions-Policy manquant — accès non restreint aux APIs sensibles (caméra, micro…)' });
  }
  if (!headers.corp || !headers.coep || !headers.coop) {
    findings.push({ severity: 'low', message: 'Headers Cross-Origin (CORP/COEP/COOP) manquants — isolation insuffisante' });
  }

  headers.versionLeaks.forEach(leak => {
    findings.push({
      severity: 'medium',
      message: `Fuite de technologie via header "${leak.header}" : "${leak.value}" — facilite le ciblage d'exploits`,
    });
  });

  cookies.issues.forEach(issue => {
    findings.push({ severity: 'medium', message: issue });
  });

  exposedFiles.forEach(file => {
    findings.push({
      severity: file.severity,
      message: `FICHIER EXPOSÉ : ${file.name} accessible publiquement (${file.url})`,
    });
  });

  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return findings;
};


const scanWebsite = async (url) => {
  let browser;
  try {
    const { default: puppeteer } = await import('puppeteer');

    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
      ],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    ];
    await page.setUserAgent(userAgents[Math.floor(Math.random() * userAgents.length)]);

    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });

    let mainResponseHeaders = {};
    page.on('response', (response) => {
      const rUrl = response.url().replace(/\/$/, '');
      const tUrl = url.replace(/\/$/, '');
      if (rUrl === tUrl || rUrl.startsWith(tUrl)) {
        mainResponseHeaders = response.headers();
      }
    });

    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 15000,
    });

    if (Object.keys(mainResponseHeaders).length === 0 && response) {
      mainResponseHeaders = response.headers();
    }

    const finalUrl = page.url();
    const siteCookies = await page.cookies();

    await browser.close();
    browser = null;

    // Analyses
    const exposedFiles = await checkSensitiveFiles(finalUrl);
    const ssl = {
      valid: finalUrl.startsWith('https'),
      protocol: finalUrl.startsWith('https') ? 'HTTPS' : 'HTTP',
    };
    const headerResult = headersScanner(mainResponseHeaders);
    const cookieResult = cookieScanner(siteCookies);
    const score = scoreCalculator(ssl, headerResult, cookieResult, exposedFiles);
    const findings = buildFindings(ssl, headerResult, cookieResult, exposedFiles);

    const riskLevel =
      score >= 80 ? 'low'
      : score >= 50 ? 'medium'
      : score >= 25 ? 'high'
      : 'critical';

    return {
      url: finalUrl,
      score,
      riskLevel,
      ssl,
      headers: headerResult,
      cookies: cookieResult,
      exposedFiles,
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
      },
      createdAt: new Date(),
    };
  } catch (err) {
    console.error('Erreur scan :', url, err.message);
    if (browser) await browser.close();

    return {
      url,
      score: 0,
      riskLevel: 'critical',
      ssl: { valid: false, protocol: 'BLOCKED/TIMEOUT' },
      headers: {
        csp: false, cspStrict: false, cspValue: '',
        hsts: false, hstsStrict: false, hstsMaxAge: 0,
        xFrame: false, xContent: false, referrer: false,
        permissionsPolicy: false, corp: false, coep: false, coop: false,
        versionLeaks: [],
      },
      cookies: { secure: false, httpOnly: false, sameSite: false, issues: [], total: 0 },
      exposedFiles: [],
      findings: [{
        severity: 'high',
        message: 'Site inaccessible — connexion refusée, timeout ou protection anti-bot détectée',
      }],
      summary: { critical: 0, high: 1, medium: 0, low: 0 },
      createdAt: new Date(),
    };
  }
};

module.exports = { scanWebsite };