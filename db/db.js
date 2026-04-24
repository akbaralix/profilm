import mongoose from "mongoose";

const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://tursunboyevakbarali807_db_user:oILBciXku5RQpVCk@cluster0.iplbvg7.mongodb.net/profilm?appName=Cluster0";

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("MongoDB ulandi");
  } catch (err) {
    console.error("MongoDB ulanishida xato:", err.message);
    process.exit(1);
  }
};

export default connectDB;
