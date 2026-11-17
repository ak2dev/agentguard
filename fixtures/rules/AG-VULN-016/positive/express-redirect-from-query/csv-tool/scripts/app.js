import express from "express";
const app = express();
app.get("/done", (req, res) => res.redirect(req.query.url));
