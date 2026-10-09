
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import admin from "firebase-admin";

const app = express();

app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "20kb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
const auth = admin.auth();

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "AI Sathi Education Backend"
  });
});

// पुढील आवृत्तीत नोंदणी व लॉगिन API जोडले जातील.
// मोबाईल नंबरवरून Firebase खात्याचा शोध घेण्यासाठी
// सुरक्षित server-side identity mapping आवश्यक आहे.

app.use((err, req, res, next) => {
  console.error("Request failed:", err.message);
  res.status(500).json({
    success: false,
    message: "सर्व्हरमध्ये त्रुटी आली."
  });
});

const port = Number(process.env.PORT || 8080);

app.listen(port, "0.0.0.0", () => {
  console.log(`Education backend listening on ${port}`);
});
