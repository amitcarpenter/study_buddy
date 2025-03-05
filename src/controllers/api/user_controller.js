import dotenv from 'dotenv';
import Msg from '../utils/message.js';
import path from 'path';
import handlebars from 'handlebars';
import fs from 'fs/promises';
import localStorage from 'localStorage';
import bcrypt from 'bcrypt';
import { sendEmail } from '../utils/emailService.js';
import { handleError, handleSuccess } from '../utils/responseHandler.js';

import {
    isUsersExistsOrNot,
    userRegistration,
    updateUserForgotPasswordOtp,
    updateUserPassword,
    fetchUsersById,
    changePassword,
    updateUsersProfile,
    fetchUsersByActivationCode,
    updateUsersByOtp,
    fetchForgotPasswordCodeByCode,
    create_blocked,
    unblockedToUsers,
    fetchBlockedListUsers,

} from '../models/user.model.js';
import {
    randomStringAsBase64Url, authenticateUser,
    hashPassword, sendHtmlResponse, comparePassword,
    generateRandomString, generateToken,


} from '../utils/user_helper.js';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


dotenv.config();

const baseurl = process.env.baseurl


export const userSignUp = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const code = Math.floor(10000 + Math.random() * 90000);
        const data = await isUsersExistsOrNot(email);
        if (data.length !== 0) {
            return handleError(res, 400, Msg.allreadyHaveAccount, []);
        } else {
            const hash = await hashPassword(password);
            const user = {
                userName: username,
                email: email.toLowerCase(),
                code: code,
                password: hash,
            };
            let create_user = await userRegistration(user);
            if (create_user) {
                const context = {
                    verification_code: code,
                    msg: Msg.verifiedMessage,
                };
                const projectRoot = path.resolve(__dirname, "../");
                const emailTemplatePath = path.join(projectRoot, "views", "signupemail.handlebars");
                const templateSource = await fs.readFile(emailTemplatePath, "utf-8");
                const template = handlebars.compile(templateSource);
                const emailHtml = template(context);
                const emailOptions = {
                    to: email,
                    subject: Msg.accountActivate,
                    html: emailHtml,
                };
                await sendEmail(emailOptions);
                return handleSuccess(res, 200, `${Msg.accountVerifiedCodeSent}.`);
            } else {
                return handleSuccess(res, 400, `${Msg.failedToUsersCreate}`);
            }
        }
    } catch (error) {
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const otpVerified = async (req, res) => {
    try {
        const { otp, isForgotPasswordPage } = req.body;
        if (isForgotPasswordPage) {
            const data = await fetchForgotPasswordCodeByCode(otp);
            if (data.length !== 0) {
                return handleSuccess(res, 200, `${Msg.otpVerified}.`);
            } else {
                return handleError(res, 400, Msg.invalidOtp);
            }
        } else {
            const data = await fetchUsersByActivationCode(otp);
            if (data.length !== 0) {
                await updateUsersByOtp(data[0]?.id);
                return handleSuccess(res, 200, `${Msg.otpVerified}.`);
            } else {
                return handleError(res, 400, Msg.invalidOtp);
            }
        }
    } catch (err) {
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const userSignIn = async (req, res) => {
    try {
        const { email, password } = req.body;
        const userData = await isUsersExistsOrNot(email);
        return authenticateUser(res, email, password, userData);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const data = await isUsersExistsOrNot(email);
        if (data.length > 0) {
            const code = Math.floor(10000 + Math.random() * 90000);
            await updateUserForgotPasswordOtp(code, email);
            const context = {
                OTP: code,
                msg: Msg.verifiedMessage,
            };
            const projectRoot = path.resolve(__dirname, "../");
            const emailTemplatePath = path.join(projectRoot, "views", "forget_template.handlebars");
            const templateSource = await fs.readFile(emailTemplatePath, "utf-8");
            const template = handlebars.compile(templateSource);
            const emailHtml = template(context);
            const emailOptions = {
                to: email,
                subject: Msg.accountActivate,
                html: emailHtml,
            };
            await sendEmail(emailOptions);
            return handleSuccess(res, 200, `${Msg.forgotPasswordOtpSend}.`);
        } else {
            return handleError(res, 400, Msg.emailNotFound, []);
        }
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const changeForgotPassword = async (req, res) => {
    try {
        const { email, password, confirm_password } = req.body;
        if (password == confirm_password) {
            const data = await isUsersExistsOrNot(email);
            if (data.length !== 0) {
                const hash = await bcrypt.hash(password, 12);
                const result2 = await updateUserPassword(hash, email);
                if (result2.affectedRows) {
                    return handleSuccess(res, 200, `${Msg.passwordChanged}.`);
                }
            } else {
                return handleError(res, 400, Msg.emailNotFound, []);
            }
        } else {
            return handleError(res, 400, Msg.passwordAndConfirmPasswordNotMatch, []);
        }
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const resetPassword = async (req, res) => {
    try {
        let {
            old_password,
            new_password,
            confirm_password
        } = req.body
        let { id } = req.user
        const data = await fetchUsersById(id);
        if (data.length > 0) {
            const match = await comparePassword(old_password, data[0].password);
            if (match) {
                if (new_password == confirm_password) {
                    const hash = await hashPassword(confirm_password);
                    let result = await changePassword(hash, id)
                    if (result.affectedRows) {
                        return handleSuccess(res, 200, Msg.passwordChanged);
                    } else {
                        return handleError(res, 400, Msg.passwordNotChanged);
                    }
                } else {
                    return handleError(res, 400, Msg.passwordsDoNotMatch);
                }
            } else {
                return handleError(res, 400, Msg.currentPasswordIncorrect, []);
            }
        } else {
            return handleError(res, 400, Msg.dataNotFound, []);
        }
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const getUserProfile = async (req, res) => {
    try {
        let { id } = req.user
        let checkUser = await fetchUsersById(id);
        checkUser.map((item) => {
            item.profileImage = item.profileImage != null ? baseurl + "/profile/" + item.profileImage : null
            item.backgroundImage = item.backgroundImage != null ? baseurl + "/profile/" + item.backgroundImage : null
            return item
        })
        return handleSuccess(res, 200, Msg.userDetailedFoundSuccessfully, checkUser[0]);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const editProfile = async (req, res) => {
    try {
        let { id } = req.user
        let profileImg = "";
        let backgroundImage = "";
        if (req.files) {
            profileImg = req.files && req.files.profileImage ? req.files.profileImage[0].filename : null;
            backgroundImage = req.files && req.files.backgroundImage ? req.files.backgroundImage[0].filename : null
        }
        let [isUserExists] = await fetchUsersById(id)
        const userProfile = {
            fullName: isUserExists?.fullName ?? req.body.fullName,
            bio: isUserExists?.bio ?? req.body.bio,
            huntingTitle: isUserExists?.huntingTitle ?? req.body.huntingTitle,
            location: isUserExists?.location ?? JSON.stringify(req.body.location),
            profileImage: isUserExists?.profileImage ?? profileImg,
            backgroundImage: isUserExists?.backgroundImage ?? backgroundImage
        };
        const result = await updateUsersProfile(userProfile, id);
        return handleSuccess(res, 200, Msg.profileUpdatedSuccessfully, result);
    } catch (err) {
        console.error(err);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const blockedToAnotherUsers = async (req, res) => {
    try {
        let { userId } = req.body
        let { id } = req.user
        let obj = {
            blocked_from: id,
            blocked_to: userId
        }
        await create_blocked(obj);
        return handleSuccess(res, 200, Msg.userBlockedSuccessfully);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const unblockedToAnotherUsers = async (req, res) => {
    try {
        let { id } = req.body
        await unblockedToUsers(id)
        return handleSuccess(res, 200, Msg.userUnBlockedSuccessfully);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

// export const fetchBlockedList = async (req, res) => {
//     try {
//         let { id } = req.body
//         let result = await fetchBlockedListUsers(id);
//         if (result.length > 0) {
//             let blockedToIds = result.map(user => user.blocked_to);
//             let blocked_user_data_fetch = await get_detail_of_blocked_users(blockedToIds);
//             let users = await fetchUserBy_Id(user_id)
//             result.forEach(blockedUser => {
//                 const blockedToId = blockedUser.blocked_to;
//                 const userDetails = blocked_user_data_fetch.find(user => user.id === parseInt(blockedToId));
//                 let profileImage = userDetails.profile_images
//                 let img
//                 if (profileImage !== null) {
//                     img = baseurl + "/profile/" + profileImage
//                 } else {
//                     img = null
//                 }
//                 let multipleImg = JSON.parse(userDetails.images)
//                 if (multipleImg != null && multipleImg.length > 0) {
//                     multipleImg = multipleImg.map((item) => {
//                         return item = baseurl + "/profile/" + item;
//                     })
//                 } else {
//                     multipleImg = []
//                 }
//                 if (userDetails) {
//                     blockedUser.fullName = userDetails.fullName;
//                     blockedUser.dob = userDetails.dob;
//                     blockedUser.profile_image = img
//                     blockedUser.uploaded_images = multipleImg;
//                     const timestamp = blocked_user_data_fetch[0].createdAt;
//                     if (timestamp) {
//                         const dateOnly = (timestamp instanceof Date ? timestamp.toISOString() : timestamp).split('T')[0];
//                         blockedUser.date = dateOnly;
//                     } else {
//                         blockedUser.date = null;
//                     }
//                 }
//             });
//             result.date = result.length > 0 && result.createdAt ? (result.createdAt instanceof Date ? result.createdAt.toISOString() : result.createdAt).split('T')[0] : null
//             return res.json({
//                 message: Msg.dataFound,
//                 status: true,
//                 data: result
//             });
//         } else {
//             return res.json({
//                 message: Msg.noBlockUsers,
//                 status: true,
//                 data: []
//             });
//         }

//     } catch (error) {
//         console.log(';error', error);
//         return res.status(500).send({
//             status: false,
//             message: Msg.err
//         });
//     }
// };


export const socialLogin = async (req, res) => {
    try {
        const { email, socialId, userName, fcmToken, socialProvider } = req.body;
        const data = await isUsersExistsOrNot(email);
        if (data.length !== 0) {
            let obj = {
                socialProvider, socialId, fcmToken
            }
            await updateUsersProfile(obj, data[0].id)
            const token = generateToken([data]);
            return handleSuccess(res, 200, `${Msg.loginSuccess}.`, token);
        } else {
            const user = {
                email,
                socialId,
                userName,
                fcmToken,
                socialProvider,
                isVerified: 1
            };
            const create_user = await userRegistration(user);
            const user_id = create_user.insertId;
            const token = generateToken([data]);
            let responseData = {
                token, user_id
            }
            return handleSuccess(res, 200, `${Msg.loginSuccess}.`, responseData);
        }
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};






export const fetchAllProjects = async (req, res) => {
    try {
        let { id } = req.user
        const data = await fetchProjectDeatils(id);
        if (data.length > 0) {
            data.map((item) => {
                item.contain = item.contain ? item.contain.split(", ").map(i => i.trim()) : [];
                item.projectImage = baseurl + "/profile/" + item.projectImage
                return item
            })
            return handleSuccess(res, 200, Msg.dataFoundSuccessful, data);
        } else {
            return handleError(res, 400, Msg.dataNotFound, []);
        }
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const getFreeDemo = async (req, res) => {
    try {
        const result = await insertFreeDemo(req.body);
        return handleSuccess(res, 200, Msg.freeDemoRegistered, result);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const fetchFreeDemo = async (req, res) => {
    try {
        const result = await fetchUsersFreeDemo();
        if (result.length === 0) {
            return handleSuccess(res, 200, Msg.freeDemoNotFound, []);
        }
        return handleSuccess(res, 200, Msg.freeDemoRegistered, result);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const tellUsAbout = async (req, res) => {
    try {
        let { demoId } = req.query
        if (!demoId) {
            return handleError(res, 200, Msg.idRequire);
        }
        const isExistsIdOrNot = await fetchUsersFreeDemoByid(demoId);
        if (isExistsIdOrNot.length === 0) {
            return handleSuccess(res, 200, Msg.freeDemoNotFoundOnGivenId, {});
        }

        const result = await insertTellaboutUs(req.body, demoId);
        return handleSuccess(res, 200, Msg.dataAddedSuccessfull, result);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const scheduledDateAndTime = async (req, res) => {
    try {
        let { demoId } = req.query
        if (!demoId) {
            return handleError(res, 200, Msg.idRequire);
        }
        const isExistsIdOrNot = await fetchUsersFreeDemoByid(demoId);
        if (isExistsIdOrNot.length === 0) {
            return handleSuccess(res, 200, Msg.freeDemoNotFoundOnGivenId, {});
        }
        const result = await insertTellaboutUs(req.body, demoId);
        return handleSuccess(res, 200, Msg.scheduleAdded, result);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const fetchProjectDetailedById = async (req, res) => {
    try {
        let { projectId } = req.query
        let { id } = req.user
        const data = await fetchProjectFeaturesDeatils(projectId);
        let transformedData = Object.values(
            data.reduce((acc, curr) => {
                const { featuresName, featuredId, subFeaturesName, subFeaturedPrice, estimated_time } = curr;
                if (!acc[featuredId]) {
                    acc[featuredId] = {
                        featuresName,
                        estimated_time: estimated_time ? estimated_time : 0,
                        totalSubFeaturedPrice: 0,
                        countSubFeaturesName: 0,
                        subFeaturesListWithPrice: []
                    };
                }
                acc[featuredId].totalSubFeaturedPrice += parseFloat(subFeaturedPrice);
                acc[featuredId].countSubFeaturesName += 1;
                acc[featuredId].subFeaturesListWithPrice.push({ subFeaturesName, subFeaturedPrice });
                return acc;
            }, {})
        );
        return handleSuccess(res, 200, Msg.dataFoundSuccessful, transformedData);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const fetchFeaturesAndThereSubFeatures = async (req, res) => {
    try {
        const data = await fetchFeaturesAndSubFeatures();
        const groupedData = Object.values(
            data.reduce((acc, { featuresName, subFeaturesName, subFeaturedPrice }) => {
                if (!acc[featuresName]) {
                    acc[featuresName] = { featuresName, subFeaturesList: [] };
                }
                acc[featuresName].subFeaturesList.push({ subFeaturesName, subFeaturedPrice });
                return acc;
            }, {})
        );
        return handleSuccess(res, 200, Msg.dataFoundSuccessful, groupedData);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};

export const addBillingInformation = async (req, res) => {
    try {
        let { id } = req.user
        let billingInfo = JSON.stringify(req.body)
        let obj = {
            user_id: id,
            billingInfo
        }
        const insertBillingData = await addBillingInfomation(obj);
        return handleSuccess(res, 200, Msg.BILLING_INFO_ADD, insertBillingData.insertedId);
    } catch (error) {
        console.error(error);
        return handleError(res, 500, Msg.internalServerError);
    }
};