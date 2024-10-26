import express from "express";
import protectRoute from "../middlewere/protectRoute.js";
import { getUserForSidebar } from "../controllers/user.controllers.js";

const router = express.Router();

router.get("/", protectRoute, getUserForSidebar );

export default router;