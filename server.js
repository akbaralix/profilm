import express from "express";
import cors from "cors";
import connectDB from "./db/db.js";
import router from "./routes/authRoutes.js";

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use("/api/auth", router);

connectDB();

app.listen(port, () => {
  console.log(`Server ishga tushdi: ${port}`);
});
