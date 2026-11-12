

const crypto = require("crypto");

const REDIS_KEY = "vortex_chords_songs";

function verifyToken(token, secret) {
  try {
    if (!token || !secret) return false;

    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const [data, signature] = parts;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(data)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return false;
    }

    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    return payload.role === "admin" &&
      Number(payload.exp) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function getToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

async function redis(command) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) {
    throw new Error("Konfigurasi Redis belum lengkap.");
  }

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(command)
  });

  if (!response.ok) {
    throw new Error("Redis tidak dapat dihubungi.");
  }

  const result = await response.json();

  if (result.error) {
    throw new Error("Redis mengembalikan kesalahan.");
  }

  return result.result;
}

async function readSongs() {
  const result = await redis(["GET", REDIS_KEY]);

  if (!result) return [];

  const songs = JSON.parse(result);

  if (!Array.isArray(songs)) {
    throw new Error("Format database lagu tidak valid.");
  }

  return songs;
}

async function writeSongs(songs) {
  await redis(["SET", REDIS_KEY, JSON.stringify(songs)]);
}

function clean(value, max = 20000) {
  return typeof value === "string"
    ? value.trim().slice(0, max)
    : "";
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  try {
    // PUBLIC: membaca daftar lagu
    if (req.method === "GET") {
      const songs = await readSongs();
      return res.status(200).json({ songs });
    }

    // ADMIN: semua perubahan harus login
    const valid = verifyToken(
      getToken(req),
      process.env.ADMIN_SECRET
    );

    if (!valid) {
      return res.status(401).json({
        error: "Akses ditolak. Silakan login sebagai admin."
      });
    }

    const songs = await readSongs();

    // TAMBAH LAGU
    if (req.method === "POST") {
      const title = clean(req.body?.title, 150);
      const artist = clean(req.body?.artist, 150);
      const category = clean(req.body?.category, 80);
      const key = clean(req.body?.key, 10);
      const lyrics = clean(req.body?.lyrics, 20000);

      if (!title || !artist || !category || !key || !lyrics) {
        return res.status(400).json({
          error: "Semua kolom wajib diisi."
        });
      }

      if (songs.length >= 1000) {
        return res.status(400).json({
          error: "Batas jumlah lagu sudah tercapai."
        });
      }

      const song = {
        id: crypto.randomUUID(),
        title,
        artist,
        category,
        key,
        lyrics
      };

      songs.unshift(song);
      await writeSongs(songs);

      return res.status(201).json({
        success: true,
        song
      });
    }

    // EDIT LAGU
    if (req.method === "PUT") {
      const id = clean(req.body?.id, 100);
      const index = songs.findIndex(song => song.id === id);

      if (index === -1) {
        return res.status(404).json({
          error: "Lagu tidak ditemukan."
        });
      }

      const title = clean(req.body?.title, 150);
      const artist = clean(req.body?.artist, 150);
      const category = clean(req.body?.category, 80);
      const key = clean(req.body?.key, 10);
      const lyrics = clean(req.body?.lyrics, 20000);

      if (!title || !artist || !category || !key || !lyrics) {
        return res.status(400).json({
          error: "Semua kolom wajib diisi."
        });
      }

      songs[index] = {
        id,
        title,
        artist,
        category,
        key,
        lyrics
      };

      await writeSongs(songs);

      return res.status(200).json({
        success: true,
        song: songs[index]
      });
    }

    // HAPUS LAGU
    if (req.method === "DELETE") {
      const id = clean(req.query?.id, 100);

      if (!id) {
        return res.status(400).json({
          error: "ID lagu tidak ditemukan."
        });
      }

      const updated = songs.filter(song => song.id !== id);

      if (updated.length === songs.length) {
        return res.status(404).json({
          error: "Lagu tidak ditemukan."
        });
      }

      await writeSongs(updated);

      return res.status(200).json({
        success: true
      });
    }

    return res.status(405).json({
      error: "Method tidak diizinkan."
    });

  } catch (error) {
    console.error("VORTEX CHORDS API:", error);

    return res.status(500).json({
      error: "Terjadi kesalahan pada server."
    });
  }
};
