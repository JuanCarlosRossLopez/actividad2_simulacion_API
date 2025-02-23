const jwt = require("jsonwebtoken");
const db = require("../models/database");

const attackController = {
  // CSRF: Transferencia sin validación
  transfer: (req, res) => {
    const { amount, toAccount } = req.body;
    const query = `INSERT INTO transfers (amount, toAccount) VALUES ('${amount}', '${toAccount}')`;

    db.query(query, (err) => {
      if (err) return res.status(500).send(err);
      res.json({
        status: "CSRF Exploit Success",
        message: `Transferred ${amount} to ${toAccount}`,
        vulnerability: "Missing CSRF token validation",
      });
    });
  },

  // JWT: No verifica firma del token JWT, pero valida el rol
  adminArea: (req, res) => {
    const token = req.headers.authorization?.split(" ")[1] || "";
    const decoded = jwt.decode(token);

    if (decoded && (decoded.role === "basic" || decoded.role === "admin")) {
      res.json({
        status: "JWT Exploit Success",
        userData: decoded,
        vulnerability: "No JWT signature verification",
      });
    } else {
      res.status(403).json({
        status: "Access Denied",
        message: "Invalid role",
        vulnerability: "No JWT signature verification",
      });
    }
  },

  // SQL Injection: Consulta directa sin sanitizar
  userSearch: (req, res) => {
    const searchTerm = req.query.term;
    const query = `SELECT * FROM users WHERE username = '${searchTerm}'`;

    db.query(query, (err, results) => {
      if (err) return res.status(500).send(err);
      res.json({
        status: "SQLi Exploit Success",
        results,
        vulnerability: "Unsanitized SQL input",
      });
    });
  },

  // XSS: No se sanitiza el output
  addComment: (req, res) => {
    const { comment, user_id } = req.body;
    const checkQuery = "SELECT * FROM comments WHERE comment = ? AND user_id = ?";
    const insertQuery = "INSERT INTO comments (comment, user_id) VALUES (?, ?)";

    db.get(checkQuery, [comment, user_id], (err, row) => {
      if (err) return res.status(500).send(err);
      if (row) {
        return res.status(400).json({
          status: "Comentario duplicado",
          message: "El comentario ya existe",
        });
      }

      db.run(insertQuery, [comment, user_id], (err) => {
        if (err) return res.status(500).send(err);
        res.json({
          status: "XSS Exploit Success",
          message: "Comment added: " + comment,
          vulnerability: "Unsanitized output",
        });
      });
    });
  },

  getAllComments: (req, res) => {
    const query = "SELECT * FROM comments";
    const user_id = req.body.user_id
    if (req.query.user_id) {
      query += ` WHERE user_id = ${user_id}`;
    }

    db.all(query, (err, results) => {
      if (err) return res.status(500).send(err);
      res.json({
        status: "XSS Exploit Success",
        results: results,
        vulnerability: "Unsanitized output",
      });
    });
  },
};

module.exports = attackController;
