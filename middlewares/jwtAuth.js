const jwt = require("jsonwebtoken");
const obtenerPasswordAleatoria = require("../utils/randomPassword");

const JWT_SECRET = obtenerPasswordAleatoria();

module.exports = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No se proporcionó token" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).json({ error: "Token inválido" });
    req.user = decoded;
    next();
  });
};