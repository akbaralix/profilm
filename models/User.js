import mongoose from "mongoose";

const linkSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      default: "custom",
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    clicked: {
      type: Number,
      required: true,
      default: 0,
    },
  },
  { _id: true },
);

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    name: {
      type: String,
      required: false,
      default: "",
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    bio: {
      type: String,
      default: "",
      trim: true,
    },
    profilePic: {
      type: String,
      default: "",
      trim: true,
    },
    publicTheme: {
      type: String,
      enum: ["ocean-glass", "dark-mode", "white-mode", "violet-classic"],
      default: "ocean-glass",
    },
    googleId: {
      type: String,
      default: "",
      trim: true,
    },
    links: {
      type: [linkSchema],
      default: [],
    },
  },
  { timestamps: true },
);

export default mongoose.model("User", userSchema);
