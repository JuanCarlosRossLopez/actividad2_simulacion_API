const express = require("express");
const router = express.Router();
const usersController = require("../controllers/usersController");

/**
 * @swagger
 * /users/register:
 *   post:
 *     summary: Registrar un nuevo usuario
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       200:
 *         description: Usuario registrado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 */
// Posible ataque: Ninguno (si se valida correctamente la entrada)
router.post("/register", usersController.registerUser);

/**
 * @swagger
 * /users/login:
 *   post:
 *     summary: Iniciar sesión
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: Token JWT
 */
// Posible ataque: Fuerza bruta (si no se implementa rate limiting)
router.post("/login", usersController.loginUser);

/**
 * @swagger
 * /users/logout:
 *   post:
 *     summary: Cerrar sesión
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 description: Token JWT a expirar
 *     responses:
 *       200:
 *         description: Sesión cerrada exitosamente
 */
// Posible ataque: Ninguno (si se valida correctamente el token)
router.post("/logout", usersController.logoutUser);

/**
 * @swagger
 * /users/user/{id}:
 *   get:
 *     summary: Obtener un usuario por ID (vulnerable a IDOR)
 *     tags: [Vulnerabilities]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del usuario
 *     responses:
 *       200:
 *         description: Usuario obtenido exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 */
// Posible ataque: IDOR (Insecure Direct Object Reference)
router.get("/user/:id", usersController.getUserById);

module.exports = router;