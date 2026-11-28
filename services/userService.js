const User=require('../models/User')
const CustomError=require('../utilis/customError')
const bcrypt=require('bcryptjs')
const {generateAccessToken,verifyToken}=require('../utilis/jwt')

//otp
const crypto = require("crypto");
const PendingRegistration = require("../models/PendingRegistration");
const { sendOtpEmail } = require("../utilis/sendEmail");

//reset password
const PasswordReset = require("../models/PasswordReset");

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



exports.resendOtpService = async (email) => {
    const normalizedEmail = email.trim().toLowerCase();

    const pendingUser = await PendingRegistration.findOne({
        email: normalizedEmail,
    });

    if (!pendingUser) {
        throw new CustomError(
            "Registration not found. Please register again.",
            404
        );
    }

    const now = Date.now();

    if (pendingUser.expiresAt <= new Date(now)) {
        await PendingRegistration.deleteOne({
            _id: pendingUser._id,
        });

        throw new CustomError(
            "Registration expired. Please register again.",
            400
        );
    }

    // Check 60-second resend cooldown
    if (pendingUser.resendAvailableAt > new Date(now)) {
        const remainingSeconds = Math.ceil(
            (pendingUser.resendAvailableAt.getTime() - now) / 1000
        );

        throw new CustomError(
            `Please wait ${remainingSeconds} seconds before requesting another OTP.`,
            429
        );
    }

    // Generate a new OTP
    const otp = crypto.randomInt(100000, 1000000).toString();

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    // Send email before replacing the previous OTP
    try {
        await sendOtpEmail(normalizedEmail, otp);
    } catch (error) {
        throw new CustomError(
            "Unable to send OTP. Please try again.",
            500
        );
    }

    // Update OTP details
    pendingUser.otpHash = otpHash;
    pendingUser.otpExpiresAt = new Date(now + 5 * 60 * 1000);
    pendingUser.resendAvailableAt = new Date(now + 60 * 1000);
    pendingUser.attempts = 0;

    await pendingUser.save();

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

// Generate password reset OTP
exports.forgotPasswordService = async (email) => {
    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
        email: normalizedEmail,
    });

    if (!user) {
        throw new CustomError("No account found with this email", 404);
    }

    if (!user.password) {
        throw new CustomError(
            "This account uses Google sign-in",
            400
        );
    }

    const otp = crypto.randomInt(100000, 1000000).toString();

    const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const now = Date.now();

    const resetData = await PasswordReset.findOneAndUpdate(
        { email: normalizedEmail },
        {
            otpHash,
            otpExpiresAt: new Date(now + 5 * 60 * 1000),
            resendAvailableAt: new Date(now + 60 * 1000),
            expiresAt: new Date(now + 15 * 60 * 1000),
            attempts: 0,
        },
        {
            upsert: true,
            new: true,
            runValidators: true,
        }
    );

    try {
        await sendOtpEmail(normalizedEmail, otp);
    } catch (error) {
        await PasswordReset.deleteOne({ _id: resetData._id });

        throw new CustomError(
            "Unable to send password reset OTP",
            500
        );
    }

    return true;
};

// Verify password reset OTP
exports.verifyPasswordResetOtpService = async (email, otp) => {
    const normalizedEmail = email.trim().toLowerCase();

    const resetData = await PasswordReset.findOne({
        email: normalizedEmail,
    });

    if (!resetData) {
        throw new CustomError(
            "Invalid or expired OTP",
            400
        );
    }

    const now = Date.now();

    if (
        resetData.expiresAt <= new Date(now) ||
        resetData.otpExpiresAt <= new Date(now)
    ) {
        await PasswordReset.deleteOne({
            _id: resetData._id,
        });

        throw new CustomError(
            "OTP has expired. Please request a new one.",
            400
        );
    }

    if (resetData.attempts >= 5) {
        await PasswordReset.deleteOne({
            _id: resetData._id,
        });

        throw new CustomError(
            "Too many incorrect attempts. Request a new OTP.",
            429
        );
    }

    const hashedOtp = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const isMatch = crypto.timingSafeEqual(
        Buffer.from(hashedOtp, "hex"),
        Buffer.from(resetData.otpHash, "hex")
    );

    if (!isMatch) {
        resetData.attempts += 1;
        await resetData.save();

        throw new CustomError(
            "Invalid OTP",
            400
        );
    }

    return true;
};

// Reset password
exports.resetPasswordService = async (email, otp, newPassword) => {
    const normalizedEmail = email.trim().toLowerCase();

    const resetData = await PasswordReset.findOne({
        email: normalizedEmail,
    });

    if (!resetData) {
        throw new CustomError("Invalid or expired OTP", 400);
    }

    const now = Date.now();

    if (
        resetData.expiresAt <= new Date(now) ||
        resetData.otpExpiresAt <= new Date(now)
    ) {
        await PasswordReset.deleteOne({ _id: resetData._id });

        throw new CustomError("OTP expired. Request a new one.", 400);
    }

    if (resetData.attempts >= 5) {
        await PasswordReset.deleteOne({ _id: resetData._id });

        throw new CustomError("Too many incorrect attempts.", 429);
    }

    const hashedOtp = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

    const isMatch = crypto.timingSafeEqual(
        Buffer.from(hashedOtp, "hex"),
        Buffer.from(resetData.otpHash, "hex")
    );

    if (!isMatch) {
        resetData.attempts += 1;
        await resetData.save();

        throw new CustomError("Invalid OTP", 400);
    }

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
        throw new CustomError("User not found", 404);
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    await PasswordReset.deleteOne({ _id: resetData._id });

    return true;
};

// Update user profile
exports.updateUserProfileService = async (userId, data) => {
    const { name, username } = data;

    if (!name?.trim() || !username?.trim()) {
        throw new CustomError("Name and username are required", 400);
    }

    const existingUsername = await User.findOne({
        username: username.trim(),
        _id: { $ne: userId }
    });

    if (existingUsername) {
        throw new CustomError("Username is already taken", 409);
    }

    const user = await User.findByIdAndUpdate(
        userId,
        {
            name: name.trim(),
            username: username.trim()
        },
        {
            new: true,
            runValidators: true
        }
    ).select("name username email isAdmin isEmailVerified");

    if (!user) {
        throw new CustomError("User not found", 404);
    }

    return user;
};