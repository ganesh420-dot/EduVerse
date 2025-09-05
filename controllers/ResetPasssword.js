const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
exports.resetPasswordToken = async (req, res) => {
  try {
    //Get email from request body
    const email = req.body.email;
    //Check user for this email, email verification
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.json({
        success: false,
        message: `This Email: ${email} is not Registered With Us Enter a Valid Email `,
      });
    }

    //generate token
    const token = crypto.randomUUID();

    //update user by adding token and expiration time
    const updatedDetails = await User.findOneAndUpdate(
      { email: email },
      {
        token: token,
        resetPasswordExpires: Date.now() + 5 * 60 * 1000,
      },
      { new: true }
    );

    // console.log("DETAILS", updatedDetails);

    const url = `http://localhost:3000/update-password/${token}`;
    //const url = `https://studynotion-edtech-project.vercel.app/update-password/${token}`;

    //Send mail containing the url
    await mailSender(
      email,
      "Password Reset Link",
      `Your Link for email verification is ${url}. Please click this url to reset your password.`
    );

    res.json({
      success: true,
      message:
        "Email Sent Successfully, Please Check Your Email to Continue Further",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Some Error in Sending the Reset Message",
    });
  }
};

//Reset Password
exports.resetPassword = async (req, res) => {
  try {
    //data fetch
    const { password, confirmPassword, token } = req.body;
    //validation
    if (confirmPassword !== password) {
      return res.json({
        success: false,
        message: "Password and Confirm Password Does not Match",
      });
    }
    //Get userDetails from Database using Token
    const userDetails = await User.findOne({ token: token });
    //If no entry present in DB - Invalid token
    if (!userDetails) {
      return res.json({
        success: false,
        message: "Token is Invalid",
      });
    }

    //Token time check
    if (userDetails.resetPasswordExpires < Date.now()) {
      return res.json({
        success: false,
        message: "Token is Expired, Please Regenerate Your Token",
      });
    }
    //Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    //Update password
    await User.findOneAndUpdate(
      { token: token },
      { password: hashedPassword },
      { new: true }
    );
    //Return response
    return res.status(200).json({
      success: true,
      message: "Password Reset Successful",
    });
  } catch (error) {
    return res.json({
      error: error.message,
      success: false,
      message: "Some Error in Updating the Password",
    });
  }
};
