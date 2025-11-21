// routes/public.js
import express from "express";

const router = express.Router();

// Example public check route
router.post("/check", async (req, res) => {
  try {
    const { url, email, ip } = req.body || {};

    // Replace this with your real IPQS or scam detection logic
    const result = {
      isScam: false,
      riskScore: 12,
      reason: "Demo response only. Implement real IPQS logic here.",
      received: { url, email, ip }
    };

    res.status(200).json(result);
  } catch (err) {
    console.error("Error in public check route:", err);
    res.status(500).json({ error: "Internal server error in check route" });
  }
});

export default router;