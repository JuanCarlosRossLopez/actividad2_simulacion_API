const db = require("../models/database");

exports.createItem = (req, res) => {
  const { name, description } = req.body;
  const query = `INSERT INTO items (name, description) VALUES ('${name}', '${description}')`;
  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID });
  });
};

exports.getAllItems = (req, res) => {
  db.all("SELECT * FROM items", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
};

exports.getItemById = (req, res) => {
  const id = req.params.id;
  const query = `SELECT * FROM items WHERE id = ${id}`;
  db.get(query, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
};

exports.updateItem = (req, res) => {
  const id = req.params.id;
  const { name, description } = req.body;
  const query = `UPDATE items SET name = '${name}', description = '${description}' WHERE id = ${id}`;
  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: this.changes });
  });
};

exports.deleteItemById = (req, res) => {
  const id = req.params.id;
  const query = `DELETE FROM items WHERE id = ${id}`;
  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
};

exports.deleteAllItems = (req, res) => {
  const query = "DELETE FROM items";
  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
};