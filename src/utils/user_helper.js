import crypto from 'crypto';
import base64url from 'base64url';
import bcrypt from 'bcrypt';
import Msg from '../utils/message.js';
import { handleError, handleSuccess } from '../utils/responseHandler.js';
import jwt from 'jsonwebtoken';

export const capitalizeFirstLetterOfWords = (str) => {
    return str.replace(/\b\w/g, (char) => char.toUpperCase());
};

export const randomStringAsBase64Url = (size) => {
    return base64url(crypto.randomBytes(size));
};

export const generateToken = (user) => {
    return jwt.sign(
        {
            data: {
                id: user.id,
            },
        },
        process.env.AUTH_SECRETKEY,
        { expiresIn: "1d" }
    );
};

// Function to authenticate user and return token
export const authenticateUser = (res, email, password, userData) => {
    if (!userData || userData.length === 0) {
        return handleError(res, 400, Msg.accountNotFound, []);
    }
    const user = userData[0];
    if (email !== user.email) {
        return handleError(res, 400, Msg.accountNotFound, []);
    }
    const match = bcrypt.compareSync(password, user.password);
    if (!match) {
        return handleError(res, 400, Msg.invalidPassword, []);
    }
    const jwt_token = generateToken(user);
    return handleSuccess(res, 200, Msg.loginSuccess, jwt_token);
};

// Function to hash a password
export const hashPassword = async (password) => {
    try {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    } catch (error) {
        console.error("Error hashing password:", error);
        throw new Error("Password hashing failed");
    }
};

// Function to compare passwords
export const comparePassword = async (password, hashedPassword) => {
    try {
        return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
        console.error("Error comparing passwords:", error);
        throw new Error("Password comparison failed");
    }
};

export const sendHtmlResponse = (res, statusCode, message) => {
    res.status(statusCode).send(`
        <div style="text-align: center; padding: 20px;">
            <h3>${message}</h3>
        </div>
    `);
};

export const generateRandomString = async (length) => {
    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
};
