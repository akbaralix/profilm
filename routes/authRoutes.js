import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "profilm-secret";
const allowedThemes = new Set([
  "ocean-glass",
  "dark-mode",
  "white-mode",
  "violet-classic",
]);

const sanitizeUser = (user) => ({
  id: user._id,
  username: user.username,
  name: user.name,
  email: user.email,
  bio: user.bio,
  profilePic: user.profilePic,
  publicTheme: user.publicTheme,
  links: user.links,
  seen: user.seen,
});

const normalizePublicLinks = (links = []) =>
  links.filter((link) => link.enabled !== false);

const createToken = (user) =>
  jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, {
    expiresIn: "7d",
  });

const getOptionalViewerUsername = (req) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.username?.toLowerCase() || null;
  } catch {
    return null;
  }
};

router.get("/username-available/:username", async (req, res) => {
  try {
    const username = req.params.username?.trim();

    if (!username || username.length < 3) {
      return res.status(400).json({
        available: false,
        message: "Username kamida 3 ta belgidan iborat bo'lishi kerak.",
      });
    }

    const user = await User.findOne({
      username: { $regex: `^${username}$`, $options: "i" },
    });

    return res.json({ available: !user });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Username tekshiruvda xatolik yuz berdi." });
  }
});

router.post("/google/check", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ message: "Email kerak." });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ exists: false });
    }

    return res.json({
      exists: true,
      token: createToken(user),
      user: sanitizeUser(user),
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Google tekshiruvda xatolik yuz berdi." });
  }
});

router.post("/google/register", async (req, res) => {
  try {
    const username = req.body.username?.trim();
    const password = req.body.password?.trim();
    const name = req.body.name;
    const email = req.body.email?.trim().toLowerCase();
    const profilePic = req.body.profilePic?.trim() || "";
    const googleId = req.body.googleId?.trim() || "";

    if (!username || !password || !email) {
      return res
        .status(400)
        .json({ message: "Username, password va email kerak." });
    }

    if (password.length < 4) {
      return res
        .status(400)
        .json({ message: "Password kamida 4 ta belgidan iborat bo'lsin." });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(409).json({ message: "Bu email bilan user mavjud." });
    }

    const existingUsername = await User.findOne({
      username: { $regex: `^${username}$`, $options: "i" },
    });
    if (existingUsername) {
      return res.status(409).json({ message: "Bu username band." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      password: hashedPassword,
      name,
      email,
      profilePic,
      googleId,
    });

    return res.status(201).json({
      message: "Akkaunt yaratildi.",
      token: createToken(user),
      user: sanitizeUser(user),
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Google registratsiyada xatolik yuz berdi." });
  }
});

router.post("/login", async (req, res) => {
  try {
    const login = req.body.login?.trim();
    const password = req.body.password?.trim();

    if (!login || !password) {
      return res
        .status(400)
        .json({ message: "Username yoki email va password kiriting." });
    }

    const user = await User.findOne({
      $or: [
        { email: login.toLowerCase() },
        { username: { $regex: `^${login}$`, $options: "i" } },
      ],
    });

    if (!user) {
      return res
        .status(401)
        .json({ message: "Login yoki password noto'g'ri." });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "Login yoki password noto'g'ri." });
    }

    return res.json({
      message: "Muvaffaqiyatli kirildi.",
      token: createToken(user),
      user: sanitizeUser(user),
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Login jarayonida xatolik yuz berdi." });
  }
});

router.get("/me", authMiddleware, async (req, res) => {
  return res.json({ user: sanitizeUser(req.user) });
});

router.put("/me", authMiddleware, async (req, res) => {
  try {
    const { username, bio, profilePic, name, publicTheme } = req.body;

    if (username && username.trim().length < 3) {
      return res
        .status(400)
        .json({ message: "Username kamida 3 ta belgidan iborat bo'lsin." });
    }

    if (
      username &&
      username.trim().toLowerCase() !== req.user.username.toLowerCase()
    ) {
      const existingUsername = await User.findOne({
        username: { $regex: `^${username.trim()}$`, $options: "i" },
      });

      if (existingUsername) {
        return res.status(409).json({ message: "Bu username band." });
      }

      req.user.username = username.trim();
    }

    req.user.bio = bio?.trim() || "";
    req.user.profilePic = profilePic?.trim() || "";
    req.user.name = name?.trim() || "";

    if (publicTheme) {
      if (!allowedThemes.has(publicTheme)) {
        return res
          .status(400)
          .json({ message: "Noto'g'ri profil andozasi tanlandi." });
      }

      req.user.publicTheme = publicTheme;
    }

    await req.user.save();

    return res.json({
      message: "Profil saqlandi.",
      user: sanitizeUser(req.user),
      token: createToken(req.user),
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Profilni saqlashda xatolik yuz berdi." });
  }
});

router.post("/me/links", authMiddleware, async (req, res) => {
  try {
    const title = req.body.title?.trim();
    const url = req.body.url?.trim();
    const type = req.body.type?.trim() || "custom";
    const enabled = req.body.enabled ?? true;

    if (!title || !url) {
      return res
        .status(400)
        .json({ message: "Link uchun title va url kerak." });
    }

    req.user.links.push({ title, url, type, clicked: 0, enabled });
    await req.user.save();

    return res.status(201).json({
      message: "Link qo'shildi.",
      links: req.user.links,
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Link qo'shishda xatolik yuz berdi." });
  }
});

router.put("/me/links/:linkId", authMiddleware, async (req, res) => {
  try {
    const link = req.user.links.id(req.params.linkId);

    if (!link) {
      return res.status(404).json({ message: "Link topilmadi." });
    }

    const title = req.body.title?.trim();
    const url = req.body.url?.trim();
    const type = req.body.type?.trim() || "custom";
    const clicked = req.body.clicked ?? 0;
    const enabled = req.body.enabled ?? true;

    if (!title || !url) {
      return res
        .status(400)
        .json({ message: "Link uchun title va url kerak." });
    }

    link.title = title;
    link.url = url;
    link.type = type;
    link.clicked = clicked;
    link.enabled = enabled;

    await req.user.save();

    return res.json({
      message: "Link yangilandi.",
      links: req.user.links,
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Linkni yangilashda xatolik yuz berdi." });
  }
});

router.post("/public/:username/links/:linkId/click", async (req, res) => {
  try {
    const { username, linkId } = req.params;
    const viewerUsername = getOptionalViewerUsername(req);

    if (viewerUsername && viewerUsername === username?.toLowerCase()) {
      return res.json({ success: true, skipped: true, reason: "self-click" });
    }

    await User.updateOne(
      {
        username: { $regex: `^${username}$`, $options: "i" },
        links: {
          $elemMatch: {
            _id: linkId,
            enabled: { $ne: false },
          },
        },
      },
      { $inc: { "links.$.clicked": 1 } },
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Xatolik yuz berdi" });
  }
});

router.delete("/me/links/:linkId", authMiddleware, async (req, res) => {
  try {
    const link = req.user.links.id(req.params.linkId);

    if (!link) {
      return res.status(404).json({ message: "Link topilmadi." });
    }

    link.deleteOne();
    await req.user.save();

    return res.json({
      message: "Link o'chirildi.",
      links: req.user.links,
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Linkni o'chirishda xatolik yuz berdi." });
  }
});

router.get("/profile/:username", async (req, res) => {
  try {
    const user = await User.findOne({
      username: { $regex: `^${req.params.username}$`, $options: "i" },
    }).select("username bio profilePic publicTheme links name");

    if (!user) {
      return res.status(404).json({ message: "Foydalanuvchi topilmadi." });
    }

    return res.json({
      user: {
        ...user.toObject(),
        links: normalizePublicLinks(user.links),
      },
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Public profilni olishda xatolik yuz berdi." });
  }
});
const cache = new Map();

router.post("/profile/:username/seen", async (req, res) => {
  try {
    const username = req.params.username?.trim();
    const viewerUsername = getOptionalViewerUsername(req);

    if (viewerUsername && viewerUsername === username?.toLowerCase()) {
      return res.json({ skipped: true, reason: "self-view" });
    }

    const ip = req.ip;

    const key = `${ip}_${username}`;
    const now = Date.now();

    const last = cache.get(key);

    if (last && now - last < 24 * 60 * 60 * 1000) {
      return res.json({ skipped: true });
    }

    cache.set(key, now);

    const user = await User.findOneAndUpdate(
      { username: { $regex: `^${username}$`, $options: "i" } },
      { $inc: { seen: 1 } },
      { returnDocument: "after" },
    );

    if (!user) {
      return res.status(404).json({ message: "Foydalanuvchi topilmadi." });
    }

    return res.json({ seen: user.seen });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Xatolik yuz berdi" });
  }
});

export default router;
