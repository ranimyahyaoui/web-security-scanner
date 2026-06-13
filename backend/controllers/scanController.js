const Scan = require("../models/Scan");
const { scanWebsite } = require("../services/scannerService");
const { isValidUrl } = require("../utils/validators");

const createScan = async (req, res) => {
  try {

    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        message: "URL required"
      });
    }

    const userId = req.user;

    const result = await scannerService.scanWebsite(url);

    const newScan = new Scan({
      userId,
      url,
      score: result.score,
      ssl: result.ssl,
      headers: result.headers,
      cookies: result.cookies,
      findings: result.findings
    });

    const saved = await newScan.save();

    return res.status(201).json(saved);

  } catch (err) {
    return res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
};


const getScans = async (req, res) => {
  try {

    const scans = await Scan.find({ userId: req.user })
      .sort({ createdAt: -1 });

    return res.json(scans);

  } catch (err) {
    return res.status(500).json(err);
  }
};


const getScanById = async (req, res) => {
  try {

    const scan = await Scan.findOne({
      _id: req.params.id,
      userId: req.user
    });

    if (!scan) {
      return res.status(404).json({
        message: "Not found"
      });
    }

    return res.json(scan);

  } catch (err) {
    return res.status(500).json(err);
  }
};

const runScan=async (req, res) => {
  const { url } = req.body;

  if (!url || !isValidUrl(url)) {
    return res.status(400).json({ message: "Format d'URL invalide ou protocole non supporté (http/https requis obligatoirement)." });
  }

  try {
    const scanResult = await scanWebsite(url);
    
    const newScan = new Scan({
      url: scanResult.url,
      score: scanResult.score,
      ssl: scanResult.ssl,
      headers: scanResult.headers,
      cookies: scanResult.cookies,
      findings: scanResult.findings,
      createdAt: scanResult.createdAt || new Date()
    });
    
    const savedScan = await newScan.save();

    res.status(200).json({
      _id: savedScan._id,
      ...scanResult
    });
  } catch (error) {
    console.error("Erreur durant le scan/enregistrement :", error.message);
    res.status(500).json({ message: "Erreur lors du scan", error: error.message });
  }};

const historyScan=async (req, res) => {
  try {
    const history = await Scan.find().sort({ createdAt: -1 }).limit(100);
    res.status(200).json(history);
  } catch (error) {
    res.status(500).json({ message: "Impossible de récupérer l'historique", error: error.message });
  }
}


const pdfScan=async (req, res) => {
  try {

    const scan = await Scan.findById(req.params.id);

    if (!scan) {
      return res.status(404).json({ message: "Scan introuvable." });
    }

    const PDFDocument = require("pdfkit");
    const doc = new PDFDocument({ margin: 50, size: "A4" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=report-${scan._id}.pdf`);

    doc.pipe(res);


    doc.rect(0, 0, 612, 80).fill("#0f172a");

    doc.fillColor("#fff")
      .fontSize(18)
      .text("WEB SECURITY REPORT", 50, 30);

    let y = 100;


    doc.fillColor("#111827").fontSize(12).text("Target URL:", 50, y);
    y += 15;

    doc.fillColor("#2563eb").text(scan.url, 50, y);
    y += 25;

    const date = scan.createdAt
      ? new Date(scan.createdAt).toLocaleString("fr-FR")
      : new Date().toLocaleString("fr-FR");

    doc.fillColor("#111827").text("Scan Date:", 50, y);
    y += 15;

    doc.fillColor("#475569").text(date, 50, y);
    y += 30;

    
    const scoreColor =
      scan.score >= 80 ? "#22c55e" :
      scan.score >= 50 ? "#f59e0b" :
      "#ef4444";

    doc.rect(50, y, 500, 50).fill("#f1f5f9");

    doc.fillColor("#111827")
      .fontSize(12)
      .text("SECURITY SCORE", 65, y + 10);

    doc.fillColor(scoreColor)
      .fontSize(20)
      .text(`${scan.score} / 100`, 65, y + 25);

    y += 80;

  
    doc.fillColor("#0f172a").fontSize(14).text("VULNERABILITIES", 50, y);
    y += 25;

    if (scan.findings?.length) {
      scan.findings.forEach((f, i) => {

        doc.fillColor("#ef4444")
          .fontSize(10)
          .text(`• Issue ${i + 1}:`, 60, y);

        y += 12;

        doc.fillColor("#334155")
          .text(f, 80, y, { width: 450 });

        y += 25;
      });
    } else {
      doc.fillColor("#16a34a")
        .text("No critical vulnerabilities detected.", 60, y);

      y += 20;
    }

    
    y += 10;

    doc.fillColor("#0f172a")
      .fontSize(14)
      .text("RECOMMENDATIONS", 50, y);

    y += 25;

    const h = scan.headers || {};

    const addReco = (title, desc) => {
      doc.fillColor("#111827").fontSize(11).text(`• ${title}`, 60, y);
      y += 15;

      doc.fillColor("#64748b").fontSize(10).text(desc, 75, y, { width: 450 });
      y += 25;
    };

    let has = false;

    if (!h.csp) {
      has = true;
      addReco(
        "Enable CSP",
        "Prevents XSS attacks by controlling allowed scripts sources."
      );
    }

    if (!h.hsts) {
      has = true;
      addReco(
        "Enable HSTS",
        "Forces HTTPS connection for secure communication."
      );
    }

    if (!h.xFrame) {
      has = true;
      addReco(
        "X-Frame-Options",
        "Prevents clickjacking attacks."
      );
    }

    if (!has) {
      doc.fillColor("#16a34a")
        .text("System follows basic security best practices.", 60, y);
    }

    
    y += 40;

    doc.fillColor("#94a3b8")
      .fontSize(9)
      .text("Generated by Web Security Scanner - PFE Project", 50, y);

    doc.end();

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "PDF generation error" });
  }
};
module.exports = {
  createScan,
  getScans,
  getScanById,
  runScan,
  historyScan,
  pdfScan
};