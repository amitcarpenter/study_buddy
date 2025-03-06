import Joi from "joi";
import ejs, { name } from 'ejs';
import path from "path";
import crypto from "crypto";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../services/send_email.js";
import { handleError, handleSuccess, joiErrorHandle } from "../../utils/responseHandler.js";
import { get_user_data_by_email } from "../../models/api/user.model.js";


dotenv.config();

const APP_URL = process.env.APP_URL;
const image_logo = process.env.LOGO_URL;
const FRONTEND_URL = process.env.FRONTEND_URL;


export const generateVerificationLink = (token, baseUrl) => {
  return `${baseUrl}/api/verify-email?token=${token}`;
};

const generateAccessToken = (payload) => {
  const JWT_SECRET = process.env.JWT_SECRET;
  const JWT_EXPIRATION = process.env.JWT_EXPIRATION;
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRATION });
};

export const register = async (req, res) => {
  try {
    const registerSchema = Joi.object({
      name: Joi.string().required(),
      email: Joi.string().required(),
      password: Joi.string().min(8).required(),
    });
    const { error, value } = registerSchema.validate(req.body);
    if (error) return joiErrorHandle(res, error);
    const { name, password, mobile_number, email } = value;
    let lower_email = email.toLowerCase();

    const [existEmail] = await get_user_data_by_email(lower_email)
    if (existEmail) {
      return handleError(res, 400, "Email already exists.");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyTokenExpiry = new Date(Date.now() + 3600000);

    const newUser = userRepository.create({
      name: name,
      mobile_number: mobile_number,
      email: lower_email,
      password: hashedPassword,
      show_password: password,
      verify_token: verifyToken,
      verify_token_expiry: verifyTokenExpiry,
    });

    const baseUrl = req.protocol + '://' + req.get('host');
    const verificationLink = generateVerificationLink(verifyToken, baseUrl);
    const emailTemplatePath = path.resolve(__dirname, '../../views/verifyAccount.ejs');
    const emailHtml = await ejs.renderFile(emailTemplatePath, { verificationLink, image_logo });

    const emailOptions = {
      to: lower_email,
      subject: "Verify Your Email Address",
      html: emailHtml,
    };

    await sendEmail(emailOptions);

    await userRepository.save(newUser);
    return handleSuccess(res, 201, `Verification link sent successfully to your email (${lower_email}). Please verify your account.`);
  } catch (error) {
    console.error('Error in register:', error);
    return handleError(res, 500, error.message);
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;
    console.log(token)
    if (typeof token !== 'string') {
      return handleError(res, 400, "Invalid token.");
    }
    const userRepository = getRepository(User);
    const user = await userRepository.findOne({
      where: {
        verify_token: token,
        verify_token_expiry: MoreThan(new Date())
      }
    });

    if (!user) {
      return res.render("sessionExpire.ejs")
    }
    user.is_verified = true;
    user.verify_token = null;
    user.verify_token_expiry = null;
    await userRepository.save(user);

    return res.render("successRegister.ejs")

  } catch (error) {
    console.error('Error in verifyEmail:', error);
    return handleError(res, 500, error.message);
  }
};

export const login_user = async (req, res) => {
  try {
    const loginSchema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().min(8).required(),
    });
    const { error, value } = loginSchema.validate(req.body);
    if (error) return joiErrorHandle(res, error);
    const { email, password } = value;
    let lower_email = email.toLowerCase()
    const userRepository = getRepository(User);
    const user = await userRepository.findOneBy({ email: lower_email });
    if (!user) {
      return handleError(res, 404, "User Not Found.");
    }

    if (user.is_verified === false) {
      return handleError(res, 400, "Please Verify your email first")
    }

    if (!user.password) {
      return handleError(res, 400, "Guest account detected. Please reset your password to continue.");
    }

    if (!user.is_active) {
      return handleError(res, 400, "Your account has been deactivated by the admin.");
    }


    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return handleError(res, 400, "Invalid credentials")
    }
    const payload = { userId: user.id, email: user.email };
    const token = generateAccessToken(payload);
    user.jwt_token = token;
    await userRepository.save(user);
    return handleSuccess(res, 200, "Login Successful.", token)
  } catch (error) {
    return handleError(res, 500, error.message);
  }
};

export const render_forgot_password_page = (req, res) => {
  try {
    return res.render("resetPassword.ejs");
  } catch (error) {
    console.error("Error rendering forgot password page:", error);
    return handleError(res, 500, "An error occurred while rendering the page")
  }
};

export const forgot_password = async (req, res) => {
  try {
    const { email } = req.body;
    const forgotPasswordSchema = Joi.object({
      email: Joi.string().email().required(),
    });
    const { error } = forgotPasswordSchema.validate(req.body);
    if (error) return joiErrorHandle(res, error);
    let lower_email = email.toLowerCase()
    const userRepository = getRepository(User);
    const user = await userRepository.findOneBy({ email: lower_email });
    if (!user) {
      return handleError(res, 404, "User Not Found")
    }
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyTokenExpiry = new Date(Date.now() + 3600000);


    if (user.is_verified === false) {
      return handleError(res, 400, "Please Verify your email first")
    }
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 3600000);
    user.reset_password_token = resetToken;
    user.reset_password_token_expiry = resetTokenExpiry;
    await userRepository.save(user);
    const resetLink = `${req.protocol}://${req.get("host")}/api/reset-password?token=${resetToken}`;
    const emailTemplatePath = path.resolve(__dirname, '../../views/forgotPassword.ejs');
    const emailHtml = await ejs.renderFile(emailTemplatePath, { resetLink, image_logo });
    const emailOptions = {
      to: email,
      subject: "Password Reset Request",
      html: emailHtml,
    };
    await sendEmail(emailOptions);
    return handleSuccess(res, 200, `Password reset link sent to your email (${email}).`);
  } catch (error) {
    console.error("Error in forgot password controller:", error);
    return handleError(res, 500, error.message);
  }
};

export const reset_password = async (req, res) => {
  try {
    const resetPasswordSchema = Joi.object({
      token: Joi.string().required(),
      newPassword: Joi.string().min(8).required().messages({
        "string.min": "Password must be at least 8 characters long",
        "any.required": "New password is required",
      }),
    });
    const { error, value } = resetPasswordSchema.validate(req.body);
    if (error) return joiErrorHandle(res, error);
    const { token, newPassword } = value;
    const userRepository = getRepository(User);
    const user = await userRepository.findOne({
      where: {
        reset_password_token: token,
        reset_password_token_expiry: MoreThan(new Date()),
      },
    });
    if (!user) {
      return handleError(res, 400, "Invalid or expired token")
    }
    if (user.show_password == newPassword) {
      return handleError(res, 400, "Password cannot be the same as the previous password.");
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    user.password = hashedPassword;
    user.show_password = newPassword;
    user.reset_password_token = null;
    user.reset_password_token_expiry = null;
    await userRepository.save(user);
    return handleSuccess(res, 200, "Password reset successfully.",)
  } catch (error) {
    console.error("Error in reset password controller:", error);
    return handleError(res, 500, error.message);
  }
};

export const render_success_register = (req, res) => {
  return res.render("successRegister.ejs")
}

export const render_success_reset = (req, res) => {
  return res.render("successReset.ejs")
}

export const getProfile = async (req, res) => {
  try {
    const user_req = req.user;
    const userRepository = getRepository(User);
    const user = await userRepository.findOneBy({ id: user_req.id });
    if (!user) {
      return handleError(res, 404, "User Not Found")
    }
    if (user.profile_image && !user.profile_image.startsWith("http")) {
      user.profile_image = `${APP_URL}${user.profile_image}`;
    }
    return handleSuccess(res, 200, "User profile fetched successfully", user);
  } catch (error) {
    return handleError(res, 500, error.message)
  }
};

export const updateProfile = async (req, res) => {
  try {
    const updateProfileSchema = Joi.object({
      name: Joi.string().required(),
      mobile_number: Joi.string().required(),
    });

    console.log(req.body)
    const { error, value } = updateProfileSchema.validate(req.body);
    if (error) return joiErrorHandle(res, error);
    const { name, mobile_number } = value;
    const user_req = req.user;
    const userRepository = getRepository(User);

    const user = await userRepository.findOne({ where: { id: user_req.id } });
    if (!user) {
      return handleError(res, 404, "User Not Found")
    }

    if (name) user.name = name;
    if (mobile_number) user.mobile_number = mobile_number;
    if (req.file) {
      let profile_image = "";
      profile_image = req.file.filename;
      user.profile_image = profile_image;
    }
    await userRepository.save(user);
    return handleSuccess(res, 200, "Profile updated successfully");

  } catch (error) {
    return handleError(res, 500, error.message);
  }
};

export const changePassword = async (req, res) => {
  try {
    const changePasswordSchema = Joi.object({
      currentPassword: Joi.string().required(),
      newPassword: Joi.string().min(8).required(),
    });
    const { error } = changePasswordSchema.validate(req.body);
    if (error) return joiErrorHandle(res, error);
    const user_req = req.user;
    const { currentPassword, newPassword } = req.body;
    const userRepository = getRepository(User);

    const user = await userRepository.findOneBy({ id: user_req.id });
    if (!user) {
      return handleError(res, 400, "User Not Found");
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return handleError(res, 400, "Current password is incorrect");
    }

    if (user.show_password == newPassword) {
      return handleError(res, 400, "Password cannot be the same as the previous password.");
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.show_password = newPassword;
    await userRepository.save(user);
    return handleSuccess(res, 200, "Password changed successfully")
  } catch (error) {
    return handleError(res, 500, error.message)
  }
};