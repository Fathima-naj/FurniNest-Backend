
const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  googleLogin,
  getLoggedInUser,
  logoutUser,
  refreshToken,
  verifyEmailOtp
} = require("../controllers/userController");

const authenticate = require("../middlewares/authMiddleware");

// Public routes
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/google", googleLogin);
router.post("/refreshToken", refreshToken);

// Protected route
router.get("/me", authenticate, getLoggedInUser);

// Logout
router.post("/logout", logoutUser);
router.post("/verify-otp", verifyEmailOtp);

module.exports = router;
