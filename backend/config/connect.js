const mongoose=require('mongoose');
const dbURI = process.env.MONGO_URI || process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/mon-projet';
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