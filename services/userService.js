const User=require('../models/User')
const CustomError=require('../utilis/customError')
const bcrypt=require('bcryptjs')
const {generateAccessToken,verifyToken}=require('../utilis/jwt')

//register user service
exports.userResgisterServices = async (data) => {
    const email = data.email.trim().toLowerCase();

    const userExist = await User.findOne({ email });

    if (userExist) {
        throw new CustomError("User already exists", 400);
    }

    const hashPassword = await bcrypt.hash(data.password, 10);

    const newUser = new User({
        name: data.name,
        email,
        password: hashPassword,
        username: data.username,
    });

    const savedUser = await newUser.save();

    return savedUser._id;
};


//login user service
exports.userLoginServices = async (email, password) => {
    const normalizedEmail = email.trim().toLowerCase();

    const userData = await User.findOne({
        email: normalizedEmail
    });

    if (!userData) {
        console.log("Login failed: User not found");
        throw new CustomError("Invalid email or password", 401);
    }

    if (!userData.password) {
        throw new CustomError("This account uses Google sign-in", 401);
    }

    const isMatch = await bcrypt.compare(
        password,
        userData.password
    );

    console.log("Password match:", isMatch);

    if (!isMatch) {
        console.log("Login failed: Password mismatch");
        throw new CustomError("Invalid email or password", 401);
    }

    if (userData.isBlock) {
        throw new CustomError("Your account has been blocked", 403);
    }

    return userData;
};

exports.refreshAccessTokenService=async(refreshToken)=>{

    //refresh token exists
    if(!refreshToken){
        throw new CustomError("Refresh token missing",401)
    }
    //verify refresh token
    const decoded=verifyToken(refreshToken,process.env.JWT_REFRESH_SECRET)
    if(!decoded){
        throw new CustomError("Invalid or expired refresh token", 403)
    }
    const user=await User.findById(decoded.id)
    if(!user){
        throw new CustomError("User not found",404)
    }
    const newAccessToken=generateAccessToken(user)
    return {newAccessToken}
}


exports.getUserDetails = async (id) => {
  const user = await User.findById(id).select(
    "name email username isAdmin isEmailVerified"
  );

  return user;
};

exports.logoutUserService=async()=>{
    return true;
}