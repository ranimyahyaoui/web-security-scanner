const mongoose=require('mongoose');
const dbURI ='mongodb://127.0.0.1:27017/web_scanner';
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
//  process.env.MONGO_URI || process.env.MONGO_URL ||