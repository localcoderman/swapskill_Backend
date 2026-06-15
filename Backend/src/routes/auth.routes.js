import { Router } from "express";
import {
  AuthHandle,
  googleAuthCallback,
  googleAuthHandler,
  handleGoogleLoginCallback,
  handleLogout,
} from "../controllers/auth.controllers.js";

const router = Router();

router.get("/google", googleAuthHandler);
router.get("/google/callback", googleAuthCallback, handleGoogleLoginCallback);
router.post('/authhandle', AuthHandle)
router.get("/logout", handleLogout);

export default router;
