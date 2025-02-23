const fs = require("fs");

function obtenerPasswordAleatoria() {
  try {
    const datos = fs.readFileSync("passwords.txt", "utf-8");
    const lineas = datos.split("\n").filter((linea) => linea.trim() !== "");

    if (lineas.length === 0) {
      throw new Error("El archivo está vacío");
    }

    const indiceAleatorio = Math.floor(Math.random() * lineas.length);
    return lineas[indiceAleatorio].trim();
  } catch (error) {
    console.error("Error al leer el archivo:", error.message);
    return "default_secret";
  }
}

module.exports = obtenerPasswordAleatoria;