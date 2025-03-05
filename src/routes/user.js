import express from 'express';
import controller from '../controllers/index.js';
import {
  userSignUp, userSignIn, emailVallidation, passwordVallidate, passwordChange,
  socialLoginValidation, tellAboutUsVallidations, scheduledDateAndTimeVallidations,
  billingFormValidation,
  handleValidationErrors
} from '../vallidation/userVallidation.js';
import { authenticateUser } from '../middleware/userAuth.js';
import { uploadProfile } from '../middleware/upload.js'

const fieldsConfig = [
  { name: 'profileImage', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 }
];

const app = express();

app.post('/signUp', userSignUp, handleValidationErrors, controller.userController.userSignUp);
app.post('/otpVerified', controller.userController.otpVerified);
app.post('/signIn', userSignIn, handleValidationErrors, controller.userController.userSignIn);
app.post('/forgotPassword', emailVallidation, handleValidationErrors, controller.userController.forgotPassword);
app.post('/changeForgotPassword', passwordVallidate, handleValidationErrors, controller.userController.changeForgotPassword);
app.post('/resetPassword', authenticateUser, passwordChange, handleValidationErrors, controller.userController.resetPassword);
app.get('/getUserProfile', authenticateUser, controller.userController.getUserProfile);
app.post("/editProfile", authenticateUser, uploadProfile.fields(fieldsConfig), controller.userController.editProfile);
app.post('/blockedToAnotherUsers', authenticateUser, controller.userController.blockedToAnotherUsers);
app.post('/unblockedToAnotherUsers', authenticateUser, controller.userController.unblockedToAnotherUsers);

app.post('/socialLogin', socialLoginValidation, handleValidationErrors, controller.userController.socialLogin);

// app.get('/fetchBlockedList', authenticateUser, controller.userController.fetchBlockedList);



export default app;
