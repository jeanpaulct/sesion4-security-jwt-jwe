const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

router.get('/', authController.redirectIfLoggedIn, authController.getLogin);
router.get('/login', authController.redirectIfLoggedIn, authController.getLogin);
router.post('/login', authController.postLogin);
router.get('/dashboard', authController.verifyToken, authController.getDashboard);
router.get('/logout', authController.logout);

module.exports = router;
