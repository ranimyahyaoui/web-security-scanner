require('dotenv').config();
const express=require('express');
const cors = require('cors');

const allowedOrigins = [
  'http://localhost:4200', 
  process.env.FRONT_URL
];


require('./config/connect');
const authRoutes=require('./routes/authRoutes');
const scanRoutes=require('./routes/scanRoutes');
const { scanWebsite } = require('./services/scannerService');
const app=express();
app.use(express.json());
app.use(cors());
app.use("/api/auth",authRoutes);
app.use("/api/scans",scanRoutes);
const PORT=process.env.PORT || 5000;
app.listen(PORT,()=>{
    console.log("serveur running");
    
})