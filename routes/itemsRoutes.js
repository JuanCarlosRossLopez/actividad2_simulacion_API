const express = require("express");
const router = express.Router();
const itemsController = require("../controllers/itemsController");

/**
 * @swagger
 * /items:
 *   post:
 *     summary: Crear un nuevo item (vulnerable a SQL Injection)
 *     tags: [Items]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Item'
 *     responses:
 *       200:
 *         description: Item creado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Item'
 */
router.post("/", itemsController.createItem);

/**
 * @swagger
 * /items:
 *   get:
 *     summary: Obtener todos los items
 *     tags: [Items]
 *     responses:
 *       200:
 *         description: Lista de items
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Item'
 */
router.get("/", itemsController.getAllItems);

/**
 * @swagger
 * /items/{id}:
 *   get:
 *     summary: Obtener un item por ID
 *     tags: [Items]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del item
 *     responses:
 *       200:
 *         description: Item obtenido exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Item'
 */
router.get("/:id", itemsController.getItemById);

/**
 * @swagger
 * /items/{id}:
 *   put:
 *     summary: Actualizar un item por ID (vulnerable a Mass Assignment)
 *     tags: [Items]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del item
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             additionalProperties:
 *               type: string
 *     responses:
 *       200:
 *         description: Item actualizado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Item'
 */
router.put("/:id", itemsController.updateItem);

/**
 * @swagger
 * /items/{id}:
 *   delete:
 *     summary: Eliminar un item por ID
 *     tags: [Items]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID del item
 *     responses:
 *       200:
 *         description: Item eliminado exitosamente
 */
router.delete("/:id", itemsController.deleteItemById);

/**
 * @swagger
 * /allitems:
 *   delete:
 *     summary: Eliminar todos los items
 *     tags: [Items]
 *     responses:
 *       200:
 *         description: Todos los items eliminados exitosamente
 */
router.delete("/", itemsController.deleteAllItems);

module.exports = router;