const express = require('express');
const router = express.Router();
const attackController = require('../controllers/attackController');

/**
 * @swagger
 * tags:
 *   name: Attack Simulations
 *   description: Endpoints para simular diferentes tipos de ataques
 */

/**
 * @swagger
 * /attack/csrf:
 *   post:
 *     summary: Simula un ataque CSRF
 *     tags: [Attack Simulations]
 *     responses:
 *       200:
 *         description: Simulación de ataque CSRF
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 message:
 *                   type: string
 *                 details:
 *                   type: object
 */
router.post('/csrf', attackController.transfer);

/**
 * @swagger
 * /attack/jwt:
 *   post:
 *     summary: Simula un ataque de JWT
 *     tags: [Attack Simulations]
 *     responses:
 *       200:
 *         description: Simulación de ataque JWT
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 message:
 *                   type: string
 *                 details:
 *                   type: object
 */
router.post('/jwt', attackController.adminArea);

/**
 * @swagger
 * /attack/sql-injection:
 *   get:
 *     summary: Simula un ataque de SQL Injection
 *     tags: [Attack Simulations]
 *     responses:
 *       200:
 *         description: Simulación de SQL Injection
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 query:
 *                   type: string
 *                 details:
 *                   type: object
 */
router.get('/sql-injection', attackController.userSearch);

/**
 * @swagger
 * /attack/xss:
 *   get:
 *     summary: Simula un ataque XSS
 *     tags: [Attack Simulations]
 *     parameters:
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *         required: false
 *         description: ID del usuario para obtener sus comentarios
 *     responses:
 *       200:
 *         description: Simulación de ataque XSS
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 payload:
 *                   type: string
 *                 details:
 *                   type: object
 */
router.get('/xss', attackController.getAllComments);

/**
 * @swagger
 * /attack/xss:
 *   post:
 *     summary: Agrega un comentario para simular un ataque XSS
 *     tags: [Attack Simulations]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               user_id:
 *                 type: string
 *               comment:
 *                 type: string
 *     responses:
 *       200:
 *         description: Comentario agregado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 message:
 *                   type: string
 *                 details:
 *                   type: object
 */
router.post('/xss', attackController.addComment);



module.exports = router;