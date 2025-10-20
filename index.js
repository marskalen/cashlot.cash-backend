// index.js
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import authRoutes from "./routes/auth.js"; // hvis dine ruter ligger i /routes

const app = express();

// 1) Tilladte origins fra ENV (komma-separeret)
const raw = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

// 2) Hjælpere: simpelt wildcard-match (fx *.vercel.app)
function matchOrigin(origin, allowed) {
  if (!allowed) return false;
  // gør fx https://*.vercel.app -> regex
  const pattern = "^" + allowed
    .replace(/\./g, "\\.")
    .replace(/\*/g, ".*") + "$";
  return new RegExp(pattern).test(origin);
}

function isAllowedOrigin(origin) {
  if (!origin) return true; // server-til-server/curl mv.
  return raw.some(allowed =>
    allowed === origin || matchOrigin(origin, allowed)
  );
}

// 3) CORS middleware m. credentials + preflight
const corsOptions = {
  origin(origin, cb) {
    if (isAllowedOrigin(origin)) return cb(null, true);
    console.warn("[CORS] Blocked origin:", origin, "Allowed:", raw);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: true,
};

app.use(cors(corsOptions));         // CORS for alle almindelige requests
app.options("*", cors(corsOptions)); // Preflight for alle ruter

app.use(express.json());
app.use(cookieParser());

// API routes
app.use("/api", authRoutes);

// Health
app.get("/health", (_req, res) => res.json({
  ok: true,
  env: process.env.NODE_ENV,
  corsOrigins: raw,
}));

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Cashlot API running on :${port}`));
