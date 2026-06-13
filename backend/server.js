require('dotenv').config();
const express=require('express');
const cors = require('cors');

const allowedOrigins = [
  'http://localhost:4200', 
  'https://votre-projet-front.vercel.app' 
];


require('./config/connect');
const authRoutes=require('./routes/authRoutes');
const scanRoutes=require('./routes/scanRoutes');
const { scanWebsite } = require('./services/scannerService');
const app=express();
app.use(express.json());
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'La politique CORS de ce site ne permet pas l\'accès depuis l\'origine spécifiée.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true 
}));
app.use("/api/auth",authRoutes);
app.use("/api/scans",scanRoutes);
const PORT=process.env.PORT || 5000;
app.listen(PORT,()=>{
    console.log("serveur running");
    
})