import express from 'express';
import { uploadFile } from '../services/uploadImage.js';



//==================================== Import Controllers ==============================
import * as authControllers from "../controllers/api/authController.js";
import { authenticateUser } from '../middleware/auth.js';


const router = express.Router();

//==================================== AUTH ==============================
router.post("/register", authControllers.register);
router.get("/verify-email", authControllers.verifyEmail);
router.post("/login", authControllers.login_user);
router.post("/forgot-password", authControllers.forgot_password);
router.get("/reset-password", authControllers.render_forgot_password_page);
router.post("/reset-password", authControllers.reset_password);
router.post("/change-password", authenticateUser, authControllers.changePassword);
router.get("/profile", authenticateUser, authControllers.getProfile);
router.post("/profile/update", authenticateUser, uploadFile, authControllers.updateProfile);
router.get("/register-success", authControllers.render_success_register);
router.get("/success-reset", authControllers.render_success_reset);
// router.post("/google-login", authControllers.social_login);



export default router;
