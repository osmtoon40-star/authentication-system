import userModel from "../models/user.model.js";
import crypto, { verify } from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import {generateOTP , getOtpHtml} from "../utils/utils.js";
import otpModel from "../models/otp.model.js";

export async function registerUser(req, res) {
    
    const {username , email , password} = req.body

    const isAlreadyRegistered = await userModel.findOne({
        $or :[
            {username},
            {email}
        ]
    })

    if(isAlreadyRegistered)
    {
        res.status(409).json({
            message:"Username or email already registered"
        })
    }

    const hashedPassword = crypto.createHash("sha256")
    .update(password)
    .digest("hex")


    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    })

    const otp = generateOTP();
    const html = getOtpHtml(otp);

    const otpHash = crypto.createHash("sha256")
    .update(otp)
    .digest("hex")

    await otpModel.create({
        email,
        user : user._id,
        otpHash
    })

    await sendEmail(
        email,
        "OTP Verification",
        `Your OTP code is ${otp}`,
        html
    )


    res.status(201).json({
        message: "User registered successfully",
        user: {
            username: user.username,
            email: user.email,
            verified : user.verified
        },
        
    });
}


export async function login(req , res){
    const {email , password} = req.body;

    const user = await userModel.findOne( 
        {email}
     )
    if(!user)    {
        return res.status(404).json({
            message : "User not found"
        })
    }

    if(!user.verified)
    {
        return res.status(401).json({
            message : "Please verify your email first"
        })
    }

    const hashedPassword = crypto.createHash("sha256")
    .update(password)
    .digest("hex")

    if(user.password !== hashedPassword)
    {
        return res.status(401).json({
            message : "Invalid credentials"
        })
    }

    // ✅ Create refresh token
    
    const refreshToken = jwt.sign(
        {user:user._id},
        config.JWT_SECRET,
        {expiresIn : "7d"}
    )

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    // ✅ Create session
    const session = await sessionModel.create({
    user: user._id,
    refreshTokenHash,
    ip: req.ip,
    userAgent: req.headers["user-agent"]
    });

    // ✅ Create access token
    const accessToken = jwt.sign(
        {
            id: user._id,
            sessionId: session._id
        },
        config.JWT_SECRET,
        { expiresIn: "15m" }
    );

     // ✅ Send refresh token in cookie
     res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge : 7*24*60*60*1000 // 7 days
    });

     res.status(200).json({
        message : "Logged in successfully",

        user : {
            username : user.username,
            email : user.email
        },
        accessToken
     })
}



export async function getMe(req , res){

    const token = req.headers.authorization?.split(" ")[1];

    if(!token)
    {
        return res.status(401).json({
            message : "token not found"
        })
    }

    const decoded = jwt.verify(token,config.JWT_SECRET)

    const user = await userModel.findById(decoded.id)

    res.status(200).json({
        message : "User fetched successfully",
        user:{
            username : user.username,
            email: user.email,
        }
    })

}


export async function refreshToken(req , res){

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message : "Refresh token not found"
        })
    }

    
        const decoded = jwt.verify(refreshToken,config.JWT_SECRET);

        

        const refreshTokenHash = crypto.createHash('sha256')
        .update(refreshToken)
        .digest('hex');

        const session = await sessionModel.findOne({
            refreshTokenHash : refreshTokenHash,
            revoked : false
        })

        if(!session){
            return res.status(404).json({
                message : "Session not found"
            })
        }

        const newAccessToken = jwt.sign({
            id:decoded.id
        },config.JWT_SECRET,
        {
            expiresIn : "15m"
        }
        )

        const newRefreshToken = crypto.createHash('sha256')
        .update(refreshToken)
        .digest('hex');

        session.refreshTokenHash = newRefreshToken;
        await session.save();

        res.cookie("refreshToken" , newRefreshToken , {
            httpOnly : true,
            secure : true,
            sameSite : "strict",
            maxAge : 7 * 24 * 60 * 60 * 1000 // 7 days

        })

        res.status(200).json({
            message : "Access token refreshed successfully",
            token : newAccessToken
        })
    
    
    
    }



export async function logout(req , res){

        const refreshToken = req.cookies.refreshToken;

        if(!refreshToken){
            return res.status(401).json({
                message : "Refresh token not found"
            })
        }
        

        
        
        

        const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

        const session = await sessionModel.findOne({
            refreshTokenHash,
            revoked : false
        })

        if(!session){
            return res.status(404).json({
                message : "Session not found"
            })
        }
        

        

       

        session.revoked = true;
        await session.save();

        res.clearCookie("refreshToken");

        res.status(200).json({
            message : "Logged out successfully"
        })
    }




export async function logoutAll(req , res){

    const refreshToken = req.cookies.refreshToken;
    
    if(!refreshToken){
        return res.status(401).json({
            message : "Refresh token not found"
        })
    }

    const deoded = jwt.verify(refreshToken,config.JWT_SECRET);

    await sessionModel.updateMany({
        user : deoded.id,
        revoked : false
    },
    {
        revoked : true
    })

    res.clearCookie("refreshToken");

    res.status(200).json({
        message : "Logged out from all sessions successfully"
    })

}


export async function verifyEmail(req , res){

    const {email , otp} = req.body;

    const user = await userModel.findOne({email});

    if(!user)
    {
        return res.status(404).json({
            message : "User not found"
        })
    }

    const otpHash = crypto.createHash("sha256")
    .update(otp)
    .digest("hex")

    const otpDoc= await otpModel.findOne({
        email,
        user : user._id,
        otpHash
    })

    if(!otpDoc)
    {
        return res.status(400).json({
            message : "Invalid OTP"
        })
    }

    const updatedUser = await userModel.findByIdAndUpdate(
        user._id,
        { verified: true },
        { new: true }
    );

    await otpModel.deleteMany({
        email,
        user : user._id
    })

    res.status(200).json({
        message : "Email verified successfully",
        user : {
            username : updatedUser.username,
            email : updatedUser.email,
            verified : updatedUser.verified
        }
    })
}



export default registerUser;