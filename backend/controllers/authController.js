const User=require('../models/User');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const register=(req,res)=>{
    let data=req.body;
    let user=new User(data);
    user.password=bcrypt.hashSync(data.password,10)
    user.save()
        .then(
            (result)=>{
                res.send(result);
            }
        )
        .catch(
            (err)=>{
                res.send(err); 
            }
        )
}
const login = (req, res) => {

  const { email, password } = req.body;

  User.findOne({ email })
    .then(user => {

      if (!user) {
        return res.status(401).json({
          message: "Email ou mot de passe invalide"
        });
      }

      const valid = bcrypt.compareSync(password, user.password);

      if (!valid) {
        return res.status(401).json({
          message: "Email ou mot de passe invalide"
        });
      }

      const payload = {
        id: user._id,
        name: user.name
      };

      const token = jwt.sign(payload, process.env.JWT_SECRET);

      return res.json({
        token,
        user
      });

    })
    .catch(err => {
      return res.status(500).json({
        message: "Erreur serveur",
        error: err.message
      });
    });
};
module.exports={
    register,login
}