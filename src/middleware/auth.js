import jwt from 'jsonwebtoken';
import { handleError } from '../utils/responseHandler.js';
import dotenv from 'dotenv';
import Msg from '../utils/message.js';
import {fetchUsersById} from '../models/user.model.js';
dotenv.config();

const JWT_SECRET = process.env.AUTH_SECRETKEY;

export const authenticateUser = async (req, res, next) => {
  try {
    const authorizationHeader = req.headers['authorization'];
    if (!authorizationHeader) {
      return handleError(res, 401, Msg.NO_TOKEN_PROVIDED);
    }
    const tokenParts = authorizationHeader.split(' ');
    if (tokenParts[0] !== 'Bearer' || !tokenParts[1]) {
      return handleError(res, 401, Msg.INVALID_OR_MISSING_TOKEN);
    }
    const token = tokenParts[1];
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return handleError(res, 401, Msg.INVALID_TOKEN);
    }
    const [user] = await fetchUsersById(decodedToken.data.id)
    if (!user) {
      return handleError(res, 404, Msg.USER_NOT_FOUND);
    }
    req.user = user;
    next();
  } catch (error) {
    return handleError(res, 500, Msg.INTERNAL_SERVER_ERROR);
  }
};
