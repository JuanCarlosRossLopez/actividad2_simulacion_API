const express = require("express");
const router = express.Router();
const logsController = require("../controllers/logsController");

/**
 * @swagger
 * /logs:
 *   post:
 *     summary: Crear un nuevo log
 *     tags: [Logs]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               level:
 *                 type: string
 *                 enum: [error, warning]
 *               message:
 *                 type: string
 *               details:
 *                 type: string
 *               timestamp:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       201:
 *         description: Log creado exitosamente
 */
router.post("/", logsController.createLog);

/**
 * @swagger
 * /logs:
 *   get:
 *     summary: Obtener todos los logs
 *     tags: [Logs]
 *     responses:
 *       200:
 *         description: Lista de logs
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   level:
 *                     type: string
 *                   message:
 *                     type: string
 *                   details:
 *                     type: string
 *                   timestamp:
 *                     type: string
 *                     format: date-time
 */
router.get("/", logsController.getLogs);

module.exports = router;