import {Router} from "express";
import * as authController from "../controller/auth.controller.js";
import { getMe } from "../controller/auth.controller.js";
const authRouter = Router();


/**
 * POST /api/auth/register
 * @desc Register a new user
 * @access Public
 */

authRouter.post("/register" , authController.registerUser);


/**
 * POST /api/auth/login
 * @desc Login a user and create a session
 * @access Public
 */
authRouter.post("/login" , authController.login);

/**
 * GET /api/auth/get-me
 * @desc Get the current user's information
 * @access Private
 */

authRouter.get("/getMe" , authController.getMe);




/**
 * GET /api/auth/refresh-token
 * @desc Refresh the access token using the refresh token
 * @access Public       
 */
authRouter.get("/refresh-token" , authController.refreshToken);



/**
 * POST /api/auth/logout
 * @desc Logout the user by revoking the current session
 * @access Private
 */
authRouter.post("/logout" , authController.logout);
 

/**
 * POST /api/auth/logout-all
 * @desc Logout the user from all sessions by revoking all sessions
 * @access Private          
 */

authRouter.get("/logout-all" , authController.logoutAll);


/**
 * GET /api/auth/verify-email
 * @desc Verify the user's email using the OTP
 * @access Public          
 */
authRouter.post("/verify-email" , authController.verifyEmail);




export default authRouter;