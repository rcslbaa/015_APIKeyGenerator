// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const { registerAdmin, loginAdmin, verifyToken } = require('./controllers/authController');
const { saveUserAndKey, getDashboardData } = require('./controllers/keyController');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json()); // Middleware untuk parsing body JSON
app.use(express.static(path.join(__dirname, 'public'))); // Menyajikan file frontend

// --- ROUTE ADMIN (Otentikasi) ---
app.post('/api/admin/register', registerAdmin);
app.post('/api/admin/login', loginAdmin);

// --- ROUTE USER/KEY GENERATOR ---
app.post('/api/key/generate', saveUserAndKey);

// --- ROUTE TERPROTEKSI (Admin Dashboard) ---
// Gunakan middleware verifyToken untuk mengamankan akses
app.get('/api/admin/dashboard', verifyToken, getDashboardData);

// --- START SERVER ---
app.listen(port, () => {
    console.log(`Server Node.js berjalan di http://localhost:${port}`);
});