const jwt=require('jsonwebtoken')

exports.generateAccessToken = (user) => {
  const payload = {
    id: user._id,
    email: user.email,
    isAdmin: user.isAdmin
  };

  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '15m'
  });
};

exports.generateRefreshToken=(user)=>{
    const payload={id:user._id}
    return jwt.sign(payload,process.env.JWT_REFRESH_SECRET,{expiresIn:"7d"})
}

exports.verifyToken=(token,secret)=>{
    try{
        return jwt.verify(token,secret)
    }catch(err){
        return null
    }
}