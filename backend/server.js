require('dotenv').config();
const express = require('express');
const cors = require('cors');
require('./config/connect');

const app = express(); 

app.use(cors());

app.use(express.json());

const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');

app.use("/api/auth", authRoutes);
app.use("/api/scans", scanRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("serveur running");
});