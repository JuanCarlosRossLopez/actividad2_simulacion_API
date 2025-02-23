const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "API Simulación",
      version: "1.0.0",
      description: "Documentación de la API de Simulación",
    },
    components: {
      schemas: {
        Item: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Nombre del item",
            },
            description: {
              type: "string",
              description: "Descripción del item",
            },
          },
        },
        User: {
          type: "object",
          properties: {
            email: {
              type: "string",
              description: "Nombre de usuario",
            },
            password: {
              type: "string",
              description: "Contraseña del usuario",
            },
          },
        },
      },
    },
  },
  apis: ["./routes/*.js"],
};

const specs = swaggerJsdoc(options);

module.exports = (app) => {
  app.use("/swagger", swaggerUi.serve, swaggerUi.setup(specs));
};