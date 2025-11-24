// controllers/authController.js
const pool = require('../db/connection'); // Koneksi database
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Ambil JWT Secret dari .env
const jwtSecret = process.env.JWT_SECRET;
const saltRounds = 10;

// --- 1. ADMIN REGISTRASI ---
exports.registerAdmin = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email dan password harus diisi.' });
    }

    try {
        // Cek apakah admin sudah terdaftar
        const [existingAdmin] = await pool.promise().query('SELECT admin_id FROM admins WHERE email = ?', [email]);
        if (existingAdmin.length > 0) {
            return res.status(409).json({ success: false, message: 'Email sudah terdaftar sebagai admin.' });
        }

        // Hash password sebelum disimpan
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Simpan admin baru ke database
        await pool.promise().query('INSERT INTO admins (email, password_hash) VALUES (?, ?)', [email, passwordHash]);

        res.status(201).json({ success: true, message: 'Registrasi admin berhasil.' });

    } catch (error) {
        console.error('Error during admin registration:', error);
        res.status(500).json({ success: false, message: 'Server error saat registrasi.' });
    }
};

// --- 2. ADMIN LOGIN ---
exports.loginAdmin = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Cari admin berdasarkan email
        const [admins] = await pool.promise().query('SELECT admin_id, password_hash FROM admins WHERE email = ?', [email]);

        if (admins.length === 0) {
            return res.status(401).json({ success: false, message: 'Email atau password salah.' });
        }

        const admin = admins[0];

        // Bandingkan password yang diinput dengan hash di DB
        const isMatch = await bcrypt.compare(password, admin.password_hash);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Email atau password salah.' });
        }

        // Buat Token JWT
        const token = jwt.sign(
            { id: admin.admin_id, email: admin.email }, 
            jwtSecret, 
            { expiresIn: '1h' } // Token berlaku 1 jam
        );

        res.json({ success: true, token, adminId: admin.admin_id });

    } catch (error) {
        console.error('Error during admin login:', error);
        res.status(500).json({ success: false, message: 'Server error saat login.' });
    }
};

// --- 3. MIDDLEWARE VERIFIKASI TOKEN (Untuk Dashboard) ---
exports.verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Akses ditolak. Token tidak tersedia.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Verifikasi dan decode token
        const decoded = jwt.verify(token, jwtSecret);
        req.admin = decoded; // Menyimpan payload admin ke objek request
        next(); // Lanjut ke handler berikutnya (getDashboardData)
    } catch (err) {
        return res.status(403).json({ success: false, message: 'Token tidak valid atau kadaluarsa.' });
    }
};