
require("dotenv").config();

const { sendOtpEmail } = require("./utilis/sendEmail");

const testEmail = async () => {
  try {
    await sendOtpEmail(
      process.env.EMAIL_USER,
      "123456"
    );

    console.log("Test email sent successfully!");
  } catch (error) {
    console.error("Email sending failed:", error.message);
  }
};

testEmail();
