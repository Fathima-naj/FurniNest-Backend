const {registerValidation,loginValidation}=require('../validation/userValidation')
const {userResgisterServices,refreshAccessTokenService, userLoginServices, getUserDetails, logoutUserService}=require('../services/userService')
const CustomError=require('../utilis/customError')
const asyncHandler=require('../utilis/asyncHandler')
const STATUS=require('../utilis/constants')
const { generateAccessToken, generateRefreshToken } = require('../utilis/jwt')


const { OAuth2Client } = require("google-auth-library");
const User = require("../models/User");

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID
);

const authCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/",
  };
};

const setAuthCookies = (res, accessToken, refreshToken) => {
  const options = authCookieOptions();

  res
    .cookie("accessToken", accessToken, {
      ...options,
      maxAge: 15 * 60 * 1000,
    })
    .cookie("refreshToken", refreshToken, {
      ...options,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
};

exports.googleLogin = asyncHandler(async (req, res) => {
  const { credential } = req.body;

  if (!process.env.GOOGLE_CLIENT_ID) {
    throw new CustomError("Google authentication is not configured", 503);
  }

  if (!credential) {
    throw new CustomError("Google credential is required", 400);
  }

  let ticket;
  try {
    ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
  } catch (error) {
    if (error.response?.status >= 500) {
      throw error;
    }
    throw new CustomError("Google credential is invalid or expired", 401);
  }

  const payload = ticket.getPayload();
  if (!payload?.sub || !payload.email || payload.email_verified !== true) {
    throw new CustomError("Google account must have a verified email", 401);
  }

  const googleId = payload.sub;
  const email = payload.email.trim().toLowerCase();
  const name = payload.name?.trim() || email.split("@")[0];
  let user = await User.findOne({ email });

  if (user) {
    if (user.googleId && user.googleId !== googleId) {
      throw new CustomError(
        "This email is linked to another Google account",
        409
      );
    }

    if (user.isBlock) {
      throw new CustomError("Your account is blocked", 403);
    }

    if (!user.googleId || !user.isEmailVerified) {
      user.googleId = googleId;
      user.isEmailVerified = true;
      await user.save();
    }
  } else {
    const username = `${email.split("@")[0]}_${Date.now()}`;

    user = await User.create({
      name,
      username,
      email,
      googleId,
      authProvider: "google",
      isEmailVerified: true,
    });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  setAuthCookies(res, accessToken, refreshToken);
  res.status(200)
    .json({
      status: STATUS.SUCCESS,
      message: "Google login successful",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        isAdmin: user.isAdmin,
      },
    });
});


exports.registerUser=asyncHandler(async(req,res)=>{

    const data=req.body;
    const {error}=registerValidation.validate(data)
    if(error) throw new CustomError(error.details[0].message,400)
    await userResgisterServices(data);
    res.status(201).json({
        status:STATUS.SUCCESS,
        message:"User registered successfully"})
})


exports.loginUser=asyncHandler(async(req,res)=>{
    const {email,password}=req.body;
    const {error}=loginValidation.validate({email,password})
    if(error) throw new CustomError(error.details[0].message,400)
    const User = await userLoginServices(email,password);

    const accessToken=generateAccessToken(User);
    const refreshToken=generateRefreshToken(User);

    setAuthCookies(res, accessToken, refreshToken);
    res.status(200)
    .json({
        status:STATUS.SUCCESS,
        message:User.isAdmin
        ?'Admin Login successfully'
        :"User login successfully",
        user: {
            _id: User._id,
            name: User.name,
            email: User.email,
            isAdmin: User.isAdmin,
          },
    });
});


//new access token generating
exports.refreshToken=asyncHandler(async(req,res)=>{
    const {refreshToken}=req.cookies;
    const {newAccessToken}=await refreshAccessTokenService(refreshToken)
    res
    .cookie("accessToken",newAccessToken,{
        ...authCookieOptions(),
        maxAge:15*60*1000,
    })
    .status(200)
    .json({
        status:STATUS.SUCCESS,
        message:"Access token refreshed"
    })
})


exports.getLoggedInUser = asyncHandler(async (req, res) => {
    const user = await getUserDetails(req.user._id);  
    if (!user) {
      throw new CustomError("User not found", 404);
    }
    res.status(200).json({user})
});

exports.logoutUser = asyncHandler(async (req, res) => {
    await logoutUserService();

    const options = authCookieOptions();
    res.clearCookie("accessToken", options);
    res.clearCookie("refreshToken", options);

    res.status(200).json({ message: 'Logged out successfully' });
  });
  
