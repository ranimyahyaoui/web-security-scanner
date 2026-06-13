const puppeteer = require('puppeteer');

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

const scoreCalculator = (ssl, headers, cookies) => {
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
  return score;
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

    const ssl = { valid: finalUrl.startsWith("https"), protocol: finalUrl.startsWith("https") ? "HTTPS" : "HTTP" };
    const headerResult = headersScanner(mainResponseHeaders);
    const cookieResult = cookieScanner(siteCookies);
    const score = scoreCalculator(ssl, headerResult, cookieResult);

    let findings = [];
    if (!ssl.valid) findings.push("Pas de chiffrement HTTPS");
    if (!headerResult.csp) findings.push("En-tête Content-Security-Policy (CSP) manquant");
    if (!headerResult.hsts) findings.push("En-tête Strict-Transport-Security (HSTS) manquant");

    return { url: finalUrl, score, ssl, headers: headerResult, cookies: cookieResult, findings, createdAt: new Date() };

  } catch (err) {
    console.error("📋 Erreur interceptée sur :", url, err.message);
    if (browser) await browser.close();

    return {
      url,
      score: 0,
      ssl: { valid: false, protocol: "BLOCKED/TIMEOUT" },
      headers: { csp: false, hsts: false, xFrame: false, xContent: false, referrer: false },
      cookies: { secure: false, httpOnly: false, sameSite: false },
      findings: ["Le site a refusé la connexion ou a mis trop de temps à répondre (Anti-Bot)."],
      createdAt: new Date()
    };
  }
};

module.exports = { scanWebsite };