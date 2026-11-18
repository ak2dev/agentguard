import express from "express";
import cors from "cors";
const app = express();
app.use(cors({ origin: ["http://localhost:5173"] }));
app.listen(8931, "127.0.0.1");
