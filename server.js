
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import admin from "firebase-admin";
import { randomUUID } from "node:crypto";

const app = express();

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
const auth = admin.auth();

app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "20kb" }));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
}));

const clean = value =>
  typeof value === "string" ? value.trim() : "";

const validPhone = value => /^[0-9]{10}$/.test(value);
const validUdise = value => /^[0-9]{11}$/.test(value);

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "AI Sathi Education Backend"
  });
});

// नवीन शाळा नोंदणी
app.post("/api/register", async (req, res) => {
  let uid;
  let phoneRef;
  let createdAuthUser = false;

  try {
    const name = clean(req.body.name);
    const phone = clean(req.body.phone);
    const udise = clean(req.body.udise);
    const schoolName = clean(req.body.schoolName);
    const password = req.body.password;

    if (
      name.length < 2 || name.length > 100 ||
      !validPhone(phone) ||
      !validUdise(udise) ||
      schoolName.length < 2 || schoolName.length > 150 ||
      typeof password !== "string" ||
      password.length < 10 || password.length > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "माहिती तपासा. पासवर्ड किमान 10 अक्षरांचा असावा."
      });
    }

    phoneRef = db.collection("phoneIndex").doc(phone);

    const existing = await phoneRef.get();
    if (existing.exists) {
      return res.status(409).json({
        success: false,
        message: "हा मोबाईल नंबर आधी नोंदणीकृत आहे."
      });
    }

    uid = randomUUID();

    const passwordHash = await bcrypt.hash(password, 12);

    // Firebase Auth user हा backend मधून तयार होतो.
    await auth.createUser({
      uid,
      displayName: name,
      disabled: false
    });
    createdAuthUser = true;

    const now = admin.firestore.Timestamp.now();
    const demoEnd = admin.firestore.Timestamp.fromMillis(
      now.toMillis() + 7 * 24 * 60 * 60 * 1000
    );

    await db.runTransaction(async transaction => {
      const phoneSnap = await transaction.get(phoneRef);

      if (phoneSnap.exists) {
        throw new Error("PHONE_EXISTS");
      }

      transaction.create(phoneRef, { uid });

      transaction.create(db.collection("users").doc(uid), {
        uid,
        name,
        phone,
        passwordHash,
        udise,
        schoolName,
        createdAt: now,
        demoStart: now,
        demoEnd,
        accountStatus: "active",
        subscriptions: {}
      });

      transaction.create(db.collection("schools").doc(uid), {
        uid,
        name,
        phone,
        udise,
        schoolName,
        createdAt: now
      });
    });

    const customToken = await auth.createCustomToken(uid);

    return res.status(201).json({
      success: true,
      message: "नोंदणी यशस्वी झाली.",
      token: customToken,
      demoEndsAt: demoEnd.toDate().toISOString()
    });
  } catch (error) {
    if (createdAuthUser && uid) {
      try {
        await auth.deleteUser(uid);
      } catch (cleanupError) {
        console.error("Account cleanup failed");
      }
    }

    if (error.message === "PHONE_EXISTS") {
      return res.status(409).json({
        success: false,
        message: "हा मोबाईल नंबर आधी नोंदणीकृत आहे."
      });
    }

    console.error("Registration failed:", error.message);
    return res.status(500).json({
      success: false,
      message: "नोंदणी पूर्ण झाली नाही. पुन्हा प्रयत्न करा."
    });
  }
});

// मोबाईल नंबर व पासवर्ड लॉगिन
app.post("/api/login", async (req, res) => {
  try {
    const phone = clean(req.body.phone);
    const password = req.body.password;

    if (
      !validPhone(phone) ||
      typeof password !== "string" ||
      password.length > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "मोबाईल नंबर किंवा पासवर्ड तपासा."
      });
    }

    const phoneSnap = await db
      .collection("phoneIndex")
      .doc(phone)
      .get();

    if (!phoneSnap.exists) {
      return res.status(401).json({
        success: false,
        message: "मोबाईल नंबर किंवा पासवर्ड चुकीचा आहे."
      });
    }

    const uid = phoneSnap.data().uid;
    const userRef = db.collection("users").doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(401).json({
        success: false,
        message: "मोबाईल नंबर किंवा पासवर्ड चुकीचा आहे."
      });
    }

    const user = userSnap.data();
    const matches = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!matches || user.accountStatus !== "active") {
      return res.status(401).json({
        success: false,
        message: "मोबाईल नंबर किंवा पासवर्ड चुकीचा आहे."
      });
    }

    const customToken = await auth.createCustomToken(uid);

    return res.json({
      success: true,
      message: "लॉगिन यशस्वी.",
      token: customToken
    });
  } catch (error) {
    console.error("Login failed:", error.message);
    return res.status(500).json({
      success: false,
      message: "लॉगिन सध्या पूर्ण होऊ शकत नाही."
    });
  }
});

// लॉगिन केलेल्या शाळेची माहिती मिळवा
app.get("/api/school", async (req, res) => {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer (.+)$/);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "आधी लॉगिन करा."
      });
    }

    const decoded = await auth.verifyIdToken(match[1]);
    const snap = await db.collection("schools")
      .doc(decoded.uid)
      .get();

    if (!snap.exists) {
      return res.status(404).json({
        success: false,
        message: "शाळेची माहिती सापडली नाही."
      });
    }

    return res.json({
      success: true,
      school: snap.data()
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "लॉगिनची वैधता तपासता आली नाही."
    });
  }
});

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
