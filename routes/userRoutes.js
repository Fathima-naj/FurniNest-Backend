
const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  googleLogin,
  getLoggedInUser,
  updateUserProfile,
  logoutUser,
  refreshToken,
  verifyEmailOtp,
  resendOtp,
  forgotPassword,
  verifyPasswordResetOtp,
  resetPassword
} = require("../controllers/userController");

const authenticate = require("../middlewares/authMiddleware");

// Public routes
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/google", googleLogin);
router.post("/refreshToken", refreshToken);

// Protected route
router.get("/me", authenticate, getLoggedInUser);
router.put("/me", authenticate, updateUserProfile);

// Logout
router.post("/logout", logoutUser);

//otp
router.post("/verify-otp", verifyEmailOtp);
router.post("/resend-otp", resendOtp);

// Password reset routes
router.post("/forgot-password", forgotPassword);
router.post("/verify-reset-otp", verifyPasswordResetOtp);
router.post("/reset-password", resetPassword);

module.exports = router;
