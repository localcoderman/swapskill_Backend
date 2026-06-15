import { generateJWTToken_email, generateJWTToken_username } from "../utils/generateJWTToken.js";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { User } from "../models/user.model.js";
import { UnRegisteredUser } from "../models/unRegisteredUser.model.js";
import dotenv from "dotenv";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
 
dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      done(null, profile);
    }
  )
);

export const googleAuthHandler = passport.authenticate("google", {
  scope: ["profile", "email"],
});

export const googleAuthCallback = passport.authenticate("google", {
  failureRedirect: `${process.env.URL}/login`,
  session: false,
});

export const handleGoogleLoginCallback = asyncHandler(async (req, res) => {
  console.log("\n******** Inside handleGoogleLoginCallback function ********");
  // console.log("User Google Info", req.user);

  const existingUser = await User.findOne({ email: req.user._json.email });

  if (existingUser) {
    const jwtToken = generateJWTToken_username(existingUser);
    const expiryDate = new Date(Date.now() + 1 * 60 * 60 * 1000);
    res.cookie("accessToken", jwtToken, { httpOnly: true, expires: expiryDate, secure: false });
    return res.redirect(`${process.env.URL}/discover`);
  }

  let unregisteredUser = await UnRegisteredUser.findOne({ email: req.user._json.email });
  if (!unregisteredUser) {
    console.log("Creating new Unregistered User");
    unregisteredUser = await UnRegisteredUser.create({
      name: req.user._json.name,
      email: req.user._json.email,
      picture: req.user._json.picture,
    });
  }
  const jwtToken = generateJWTToken_email(unregisteredUser);
  const expiryDate = new Date(Date.now() + 0.5 * 60 * 60 * 1000);
  res.cookie("accessTokenRegistration", jwtToken, { httpOnly: true, expires: expiryDate, secure: false });
  return res.redirect(`${process.env.URL}/register`);
});
          


export const handleLogout = (req, res) => {
  console.log("\n******** Inside handleLogout function ********");
  res.clearCookie("accessToken");
  return res.status(200).json(new ApiResponse(200, null, "User logged out successfully"));
};


export const AuthHandle = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

   if (!email.match(/^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$/)) {
      throw new ApiError(400, "Please provide valid email");
    }

  // 1. Check karo kya user pehle se exist karta hai?
  const existingUser = await UnRegisteredUser.findOne({ email });

  if (existingUser) {
    // SCENARIO 1: User mil gaya, toh Login karo
    const isPasswordValid = await existingUser.comparePassword(password);
    
    if (!isPasswordValid) {
      return res.status(401).json(new ApiResponse(401, null, "Invalid password"));
    }

    const jwtToken = generateJWTToken_username(existingUser);
     return console.log(jwtToken);
    
    res.cookie("accessToken", jwtToken, { httpOnly: true, secure: false });
    
    return res.status(200).json(new ApiResponse(200, { user: existingUser }, "Login successful"));
   
  }

  // SCENARIO 2: User nahi mila, toh account banao aur Register page par bhejo
  console.log("Creating new Unregistered User");
  
  const unregisteredUser = await UnRegisteredUser.create({
    name: name,
    email: email,
    password: password, // Note: Ye register hone se pehle ka data hai
  });

  const jwtToken = generateJWTToken_email(unregisteredUser);
  res.cookie("accessTokenRegistration", jwtToken, { httpOnly: true, secure: false });
  // Redirect client ko batayega ki ab register form fill karna hai
  return res.status(201).json(new ApiResponse(201, { redirect: "/register" }, "New user, please complete registration"));
});

  