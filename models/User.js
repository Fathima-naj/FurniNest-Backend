
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },

    username: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
    },

    // Optional because Google users don't need a password
    password: {
      type: String,
      default: undefined,
    },

    googleId: {
      type: String,
      default: null,
    },

    authProvider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
    },

    isAdmin: {
      type: Boolean,
      required: true,
      default: false,
    },

    isBlock: {
      type: Boolean,
      required: true,
      default: false,
    },

    isEmailVerified: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", UserSchema);
