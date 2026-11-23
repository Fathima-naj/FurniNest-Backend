const User=require('../models/User')
const CustomError=require('../utilis/customError')
const bcrypt=require('bcryptjs')
const {generateAccessToken,verifyToken}=require('../utilis/jwt')

const crypto = require("crypto");
const PendingRegistration = require("../models/PendingRegistration");
const { sendOtpEmail } = require("../utilis/sendEmail");

//register user service


exports.userResgisterServices = async (data) => {
    const email = data.email.trim().toLowerCase();

    // Check whether the user already exists
    const userExist = await User.findOne({ email });

    if (userExist) {
        throw new CustomError("User already exists", 400);
    }

    // Generate username automatically
    const baseUsername =
        email.split("@")[0]
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "")
        .slice(0, 10) || "user";

    let username = baseUsername;

    while (
        await User.exists({ username }) ||
        await PendingRegistration.exists({ username })
    ) {
        const suffix = crypto.randomInt(1000, 10000);
        username = `${baseUsername}_${suffix}`;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(data.password, 10);

    // Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 1000000).toString();

    // Hash OTP before storing
    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const now = Date.now();

    // Store pending registration
    const pendingUser = await PendingRegistration.findOneAndUpdate(
        { email },
        {
            name: data.name,
            username,
            email,
            password: hashedPassword,
            otpHash,
            otpExpiresAt: new Date(now + 5 * 60 * 1000),
            resendAvailableAt: new Date(now + 60 * 1000),
            expiresAt: new Date(now + 30 * 60 * 1000),
            attempts: 0,
        },
        {
            upsert: true,
            new: true,
            runValidators: true,
            setDefaultsOnInsert: true,
        }
    );

    try {
        await sendOtpEmail(email, otp);
    } catch (error) {
        await PendingRegistration.deleteOne({
            _id: pendingUser._id,
        });

        throw new CustomError("Unable to send verification email", 500);
    }

    return true;
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