const bcrypt = require("bcrypt"); // Para hashear contraseñas
const jwt = require("jsonwebtoken");
const db = require("../models/database");
const obtenerPasswordAleatoria = require("../utils/randomPassword");


const JWT_SECRET = obtenerPasswordAleatoria();
const JWT_EXPIRATION = "1h"; // El token expira en 1 hora

exports.registerUser = (req, res) => {
  const { email, password, role = 'user' } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email y password son requeridos" });
  }

  const checkUserQuery = `SELECT * FROM users WHERE email = ?`;
  db.get(checkUserQuery, [email], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) return res.status(400).json({ error: "El usuario ya existe" });

    // Hashear la contraseña
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) return res.status(500).json({ error: "Error al hashear la contraseña" });

      const insertUserQuery = `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`;
      db.run(insertUserQuery, [email, hashedPassword, role], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, email, role });
      });
    });
  });
};

exports.loginUser = (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email y password son requeridos" });
  }

  const query = `SELECT * FROM users WHERE email = ?`;
  db.get(query, [email], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: "Credenciales inválidas" });

    // Comparar contraseñas hasheadas
    bcrypt.compare(password, row.password, (err, isMatch) => {
      if (err) return res.status(500).json({ error: "Error al verificar la contraseña" });
      if (!isMatch) return res.status(401).json({ error: "Credenciales inválidas" });

      // Generar y firmar el token
      const token = jwt.sign({ id: row.id, email: row.email, role: row.role }, JWT_SECRET, { expiresIn: JWT_EXPIRATION });

      const insertSessionQuery = `INSERT INTO sessions (user_id, token) VALUES (?, ?)`;
      db.run(insertSessionQuery, [row.id, token], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: row.id, token, role: row.role });
      });
    });
  });
};

exports.logoutUser = (req, res) => {
  const token = req.body.token;
  if (!token) {
    return res.status(400).json({ error: "Token no proporcionado" });
  }

  // Eliminar el token de la tabla sessions
  const deleteSessionQuery = `DELETE FROM sessions WHERE token = ?`;
  db.run(deleteSessionQuery, [token], function (err) {
    if (err) return res.status(500).json({ error: err.message });

    // Si el token se eliminó correctamente, guardarlo en la tabla expired_tokens
    if (this.changes > 0) {
      const insertExpiredTokenQuery = `INSERT INTO expired_tokens (token) VALUES (?)`;
      db.run(insertExpiredTokenQuery, [token], function (err) {
        if (err) return res.status(500).json({ error: "Error al guardar el token en la lista de tokens expirados" });
        res.json({ message: "Sesión cerrada y token invalidado correctamente" });
      });
    } else {
      res.status(404).json({ error: "Token no encontrado en la tabla de sesiones" });
    }
  });
};

exports.getUserById = (req, res) => {
  const id = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${id}`;
  db.get(query, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
};

exports.getExpiredTokens = (req, res) => {
  const query = `SELECT * FROM expired_tokens`;

  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Error al obtener tokens expirados", details: err.message });
    }
    res.json({ tokens: rows });
  });
};

exports.getUsers = (req, res) => {
  const query = `SELECT * FROM users`;

  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Error al obtener usuarios", details: err.message });
    }
    res.json({ users: rows });
  });
}
