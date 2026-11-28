const {registerValidation,loginValidation}=require('../validation/userValidation')
const {
    userResgisterServices,
    refreshAccessTokenService,
    userLoginServices,
    resetPasswordService,
    forgotPasswordService,
    verifyPasswordResetOtpService,
    getUserDetails,
    logoutUserService,
    resendOtpService,
    updateUserProfileService
} = require('../services/userService');
const CustomError=require('../utilis/customError')
const asyncHandler=require('../utilis/asyncHandler')
const STATUS=require('../utilis/constants')
const { generateAccessToken, generateRefreshToken } = require('../utilis/jwt')

//otp
const crypto = require("crypto");
const PendingRegistration = require("../models/PendingRegistration");

//google auth
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



exports.registerUser = asyncHandler(async (req, res) => {
    const data = req.body;

    const { error } = registerValidation.validate(data);

    if (error) {
        throw new CustomError(error.details[0].message, 400);
    }

    await userResgisterServices(data);

    res.status(200).json({
        status: STATUS.SUCCESS,
        message: "OTP sent successfully. Please verify your email.",
    });
});


exports.verifyEmailOtp = asyncHandler(async (req, res) => {
    const email = req.body.email?.trim().toLowerCase();
    const otp = req.body.otp?.trim();

    if (!email || !otp || !/^\d{6}$/.test(otp)) {
        throw new CustomError("Please enter a valid 6-digit OTP", 400);
    }

    const pendingUser = await PendingRegistration.findOne({ email });

    if (!pendingUser) {
        throw new CustomError(
            "Registration not found. Please register again.",
            404
        );
    }

    if (pendingUser.expiresAt <= new Date()) {
        await PendingRegistration.deleteOne({ _id: pendingUser._id });

        throw new CustomError("Registration expired. Please register again.", 400);
    }

    if (pendingUser.otpExpiresAt <= new Date()) {
        throw new CustomError("OTP expired. Please request a new OTP.", 400);
    }

    if (pendingUser.attempts >= 5) {
        throw new CustomError("Too many incorrect attempts. Request a new OTP.", 429);
    }

    const submittedHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const isOtpValid = crypto.timingSafeEqual(
        Buffer.from(submittedHash, "hex"),
        Buffer.from(pendingUser.otpHash, "hex")
    );

    if (!isOtpValid) {
        pendingUser.attempts += 1;
        await pendingUser.save();

        throw new CustomError("Invalid OTP. Please try again.", 400);
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
        await PendingRegistration.deleteOne({ _id: pendingUser._id });
        throw new CustomError("User already exists", 409);
    }

    await User.create({
        name: pendingUser.name,
        username: pendingUser.username,
        email: pendingUser.email,
        password: pendingUser.password,
        isEmailVerified: true,
        authProvider: "local",
    });

    await PendingRegistration.deleteOne({ _id: pendingUser._id });

    res.status(201).json({
        status: STATUS.SUCCESS,
        message: "Email verified and account created successfully.",
    });
});


exports.resendOtp = asyncHandler(async (req, res) => {
    const email = req.body.email;

    if (!email || typeof email !== "string") {
        throw new CustomError("Email is required", 400);
    }

    await resendOtpService(email);

    res.status(200).json({
        status: STATUS.SUCCESS,
        message: "A new OTP has been sent to your email.",
    });
});

// Forgot password - send OTP
exports.forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email || typeof email !== "string") {
        throw new CustomError("Valid email is required", 400);
    }

    await forgotPasswordService(email);

    res.status(200).json({
        status: STATUS.SUCCESS,
        message: "If an account exists, a password reset OTP has been sent.",
    });
});


// Verify password reset OTP
exports.verifyPasswordResetOtp = asyncHandler(async (req, res) => {
    const { email, otp } = req.body;

    if (
        !email ||
        typeof email !== "string" ||
        !otp ||
        !/^\d{6}$/.test(otp)
    ) {
        throw new CustomError("Valid email and 6-digit OTP are required", 400);
    }

    await verifyPasswordResetOtpService(email, otp);

    res.status(200).json({
        status: STATUS.SUCCESS,
        message: "OTP verified successfully.",
    });
});


// Reset password
exports.resetPassword = asyncHandler(async (req, res) => {
    const { email, otp, newPassword } = req.body;

   if (
    !email ||
    typeof email !== "string" ||
    !otp ||
    !/^\d{6}$/.test(otp) ||
    !newPassword ||
    typeof newPassword !== "string" ||
    newPassword.length < 6
) {
    throw new CustomError(
        "Email, valid OTP and password (minimum 6 characters) are required",
        400
    );
}

    await resetPasswordService(email, otp, newPassword);

    res.status(200).json({
        status: STATUS.SUCCESS,
        message: "Password reset successfully.",
    });
});


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
  
// Update logged-in user's profile
exports.updateUserProfile = asyncHandler(async (req, res) => {
    const updatedUser = await updateUserProfileService(
        req.user._id,
        req.body
    );

    res.status(200).json({
        status: STATUS.SUCCESS,
        message: "Profile updated successfully",
        user: updatedUser
    });
});