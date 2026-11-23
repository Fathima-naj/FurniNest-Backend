
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

exports.sendOtpEmail = async (email, otp) => {
  await transporter.sendMail({
    from: `"FurniNest" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "FurniNest - Email Verification OTP",
    text: `Your FurniNest verification OTP is ${otp}. It expires in 5 minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Welcome to FurniNest!</h2>
        <p>Use the following OTP to verify your email address:</p>
        <h1 style="letter-spacing: 8px;">${otp}</h1>
        <p>This OTP expires in 5 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
      </div>
    `,
  });
};
