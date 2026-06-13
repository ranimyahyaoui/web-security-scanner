const express = require("express");
const router = express.Router();
const ScanModel = require("../models/Scan"); 
const PDFDocument = require("pdfkit"); 

const { createScan, getScans, getScanById,runScan,historyScan,pdfScan } = require("../controllers/scanController");
const { protect } = require("../middleware/authMiddleware");
const { scanWebsite } = require("../services/scannerService");


const { isValidUrl } = require("../utils/validators"); 

router.post("/run",runScan);
router.get("/history",historyScan );
router.get("/export-pdf/:id", pdfScan);
router.post("/scan", protect, createScan);
router.get("/scans", protect, getScans);
router.get("/scans/:id", protect, getScanById);

module.exports = router;