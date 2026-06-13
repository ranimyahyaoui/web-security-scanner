require('dotenv').config();
const mongoose=require('mongoose');
const dbURI =process.env.MONGO_URL;
mongoose.connect(dbURI)
    .then(
        ()=>{
            console.log('connected');
            
        }
    )
    .catch(
        (err)=>{
            console.log(err);
        }
    )
