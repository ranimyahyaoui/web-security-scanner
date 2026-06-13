const mongoose=require('mongoose');
const Scan=mongoose.model('Scan',{
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"User"
    },
    url:{
        type:String
    },
    score:{
        type:Number
    },
    ssl:{
        type:Object
    },
    headers:{
        type:Object
    },
    cookies:{
        type:Object
    },
    findings:{
        type: Array
    },
    timestamps:{
        type:Boolean,
        default:true
    }
})
module.exports=Scan;