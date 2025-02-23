const express = require("express");
const bodyParser = require("body-parser");
const swaggerSetup = require("./config/swagger");
const db = require("./models/database");
const itemsRoutes = require("./routes/itemsRoutes");
const usersRoutes = require("./routes/usersRoutes");
const logsRoutes = require("./routes/logsRoutes");
const attackRoutes = require('./routes/attackRoutes');
const errorHandler = require("./middlewares/errorHandler");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());
swaggerSetup(app);

// Redirección a Swagger como punto inicial
app.get("/", (req, res) => {
  res.redirect("/swagger");
});

// Rutas
app.use("/items", itemsRoutes);
app.use("/users", usersRoutes);
app.use("/logs", logsRoutes);
app.use('/attack', attackRoutes);

// Middleware de errores
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});

process.on("SIGINT", () => {
  db.close((err) => {
    if (err) {
      console.error("Error al cerrar la base de datos:", err.message);
    } else {
      console.log("Conexión a la base de datos cerrada.");
    }
    process.exit(0);
  });
});
