const jwt = require("jsonwebtoken");
const obtenerPasswordAleatoria = require("../utils/randomPassword");

const JWT_SECRET = obtenerPasswordAleatoria();

module.exports = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No se proporcionó token" });

  // Verificar si el token está en la tabla de tokens expirados
  const checkExpiredTokenQuery = `SELECT * FROM expired_tokens WHERE token = ?`;
  db.get(checkExpiredTokenQuery, [token], (err, row) => {
    if (err) return res.status(500).json({ error: "Error al verificar el token" });
    if (row) return res.status(401).json({ error: "Token inválido o expirado" });

    // Si no está en la lista de tokens expirados, verificar su validez
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ error: "Token inválido o expirado" });
      req.user = decoded; // Guardamos los datos del usuario en la request
      next();
    });
  });
};
