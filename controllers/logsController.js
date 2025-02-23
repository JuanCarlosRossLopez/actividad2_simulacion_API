const db = require("../models/database");

exports.createLog = (req, res) => {
  const { level, message, details, timestamp } = req.body;
  const query = `INSERT INTO logs (level, message, details, timestamp) VALUES (?, ?, ?, ?)`;
  db.run(query, [level, message, details, timestamp], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID });
  });
};

exports.getLogs = (req, res) => {
  const query = `SELECT * FROM logs`;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
};