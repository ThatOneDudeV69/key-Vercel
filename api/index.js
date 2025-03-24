const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
require("dotenv").config(); // Load environment variables

// Load secret key and allowed User-Agent
const SECRET = process.env.SECRET_KEY;
const ALLOWED_USER_AGENT = process.env.ALLOWED_USER_AGENT;

if (!SECRET) {
    throw new Error("SECRET_KEY is missing in environment variables!");
}

if (!ALLOWED_USER_AGENT) {
    throw new Error("ALLOWED_USER_AGENT is missing in environment variables!");
}

// Generate HMAC signature
function generateHMAC(data, secret) {
    return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

// API endpoint
export default function handler(req, res) {
    if (req.method !== "GET") {
        return res.status(405).json({ success: false, message: "Method Not Allowed" });
    }

    const { hwid, key, signature } = req.query;
    const userAgent = req.headers["user-agent"];

    // Verify User-Agent
    if (userAgent !== ALLOWED_USER_AGENT) {
        return res.status(403).json({ success: false, message: "Forbidden: Invalid User-Agent" });
    }

    // Check for missing parameters
    if (!hwid || !key || !signature) {
        return res.status(400).json({ success: false, message: "Missing parameters" });
    }

    // Verify HMAC signature
    const expectedSignature = generateHMAC(hwid + key, SECRET);
    if (signature !== expectedSignature) {
        return res.status(403).json({ success: false, message: "Signature mismatch" });
    }

    const filePath = path.join(process.cwd(), "keys.json");
    if (!fs.existsSync(filePath)) {
        return res.status(500).json({ success: false, message: "keys.json not found" });
    }

    const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const user = data.find(entry => entry.hwid === hwid && entry.key === key);

    if (!user) {
        return res.status(403).json({ success: false, message: "Invalid HWID or key" });
    }

    // Check expiration
    const expiryDate = new Date(user.expiry);
    const currentDate = new Date();
    if (currentDate > expiryDate) {
        return res.status(403).json({ success: false, message: "Key expired" });
    }

    return res.json({ success: true });
}


