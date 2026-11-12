

const crypto = require("crypto");

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));

  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function signToken(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  return `${data}.${signature}`;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method tidak diizinkan." });
  }

  const password = process.env.ADMIN_PASSWORD;
  const secret = process.env.ADMIN_SECRET;

  if (!password || !secret) {
    return res.status(500).json({
      error: "Environment admin belum dikonfigurasi."
    });
  }

  const submittedPassword = req.body?.password;

  if (
    typeof submittedPassword !== "string" ||
    !safeEqual(submittedPassword, password)
  ) {
    return res.status(401).json({
      error: "Password admin salah."
    });
  }

  const now = Math.floor(Date.now() / 1000);

  const token = signToken({
    role: "admin",
    iat: now,
    exp: now + 8 * 60 * 60
  }, secret);

  return res.status(200).json({
    success: true,
    token
  });
};
