import jwt from "jsonwebtoken";
import { handleError } from "../utils/responseHandler.js";
import express from "express";
import dotenv from "dotenv";


dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET ;


export const authenticateUser = async (req, res, next) => {
    try {
        const authorizationHeader = req.headers['authorization'];
        if (!authorizationHeader) {
            return handleError(res, 401, "Unauthorized: No token provided")
        }
        const tokenParts = authorizationHeader.split(' ');
        if (tokenParts[0] !== 'Bearer' || tokenParts[1] === 'null' || !tokenParts[1]) {
            return handleError(res, 401, "Unauthorized: Invalid or missing token");
        }
        const token = tokenParts[1];

        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET)
        } catch (err) {
            return handleError(res, 401, "Unauthorized: Invalid token");
        }


        const userRepository = getRepository(User);
        console.log(decodedToken.email, "User Connected");

        const user = await userRepository.findOneBy({ id: decodedToken.userId });
        if (!user) {
            return handleError(res, 404, "User Not Found")

        }
        req.user = user;
        next();
    } catch (error) {
        return handleError(res, 500, error.message)
    }
};

export const authenticateAdmin = async (req, res, next) => {
    try {
        const authorizationHeader = req.headers['authorization'];
        if (!authorizationHeader) {
            return handleError(res, 401, "Unauthorized: No token provided")
        }
        const tokenParts = authorizationHeader.split(' ');
        if (tokenParts[0] !== 'Bearer' || tokenParts[1] === 'null' || !tokenParts[1]) {
            return handleError(res, 401, "Unauthorized: Invalid or missing token");
        }
        const token = tokenParts[1];
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            return handleError(res, 401, "Unauthorized: Invalid token");
        }
        const adminRepository = getRepository(Admin);
        console.log(decodedToken.email, "Admin Connected");
        const admin = await adminRepository.findOne({ where: { id: decodedToken.adminId } });
        if (!admin) {
            return handleError(res, 404, "Admin Not Found")
        }
        req.admin = admin;
        next();
    } catch (error) {
        return handleError(res, 500, error.message)
    }
};


