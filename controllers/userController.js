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


exports.googleLogin = asyncHandler(async (req, res) => {
  const { credential } = req.body;

  if (!credential) {
    throw new CustomError("Google credential is required", 400);
  }

  // 1. Verify Google's ID token
  const ticket = await googleClient.verifyIdToken({
    idToken: credential,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  // 2. Get verified Google user details
  const payload = ticket.getPayload();

  const {
    sub: googleId,
    email,
    name,
    email_verified,
  } = payload;

  if (!email || !email_verified) {
    throw new CustomError("Google email is not verified", 401);
  }

  // 3. Find existing user using email
  let user = await User.findOne({ email });

  if (user) {
    // Prevent linking a different Google account
    if (user.googleId && user.googleId !== googleId) {
      throw new CustomError(
        "This email is linked to another Google account",
        409
      );
    }

    if (user.isBlock) {
      throw new CustomError("Your account is blocked", 403);
    }

    // Link Google to an existing email account
   if (!user.googleId) {
  user.googleId = googleId;
}

user.isEmailVerified = true;
await user.save();

    user.isEmailVerified = true;
  } else {
    // 4. Create a new Google user
    const username =
      `${email.split("@")[0]}_${Date.now()}`;

    user = await User.create({
      name,
      username,
      email,
      googleId,
      authProvider: "google",
      isEmailVerified: true,
    });
  }

  // 5. Generate your existing JWT tokens
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // 6. Set existing authentication cookies
  res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: false,
      maxAge: 30 * 60 * 1000,
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .status(200)
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
    console.log("Access Token:", accessToken);
    console.log("Refresh Token:", refreshToken);

    res
    .cookie("accessToken",accessToken,{
        httpOnly:true,
        secure:false,
        maxAge:30*60*1000,

    })
    .cookie("refreshToken",refreshToken,{
        httpOnly:true,
        secure:false,
        maxAge:7*24*60*60*1000,
    })
    .status(200)
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
        httpOnly:true,
        secure:false,
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
  
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: '/'
    });
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: '/'
    });
  
    res.status(200).json({ message: 'Logged out successfully' });
  });
  
