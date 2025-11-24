// controllers/keyController.js
const pool = require('../db/connection');
const crypto = require('crypto');
const moment = require('moment'); // Untuk manajemen tanggal expiry key (npm install moment)

// --- Fungsi Helper untuk Generate Key dan Hash ---
function generateApiKey() {
    // String acak yang akan menjadi API Key
    const key = crypto.randomBytes(32).toString('hex'); 
    
    // Hash key untuk disimpan di database (keamanan)
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    
    return { key, hash };
}

// --- 1. SIMPAN USER DAN KEY (Rute /api/key/generate) ---
exports.saveUserAndKey = async (req, res) => {
    // Ingat: Client-side JS Anda mengirim first_name, last_name, email
    const { first_name, last_name, email } = req.body;

    if (!first_name || !email) {
        return res.status(400).json({ success: false, message: 'First Name dan Email harus diisi.' });
    }

    // 1. Generate Key
    const { key: apiKey, hash: apiKeyHash } = generateApiKey();
    
    // Tentukan tanggal kadaluarsa (misalnya, 1 tahun dari sekarang)
    const expiryDate = moment().add(1, 'years').format('YYYY-MM-DD');

    let connection;
    try {
        connection = await pool.promise().getConnection();
        await connection.beginTransaction(); // Mulai transaksi

        // A. Masukkan data User
        const [userResult] = await connection.query(
            'INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)',
            [first_name, last_name, email]
        );
        const userId = userResult.insertId;

        // B. Masukkan data API Key (menggunakan user_id yang baru)
        await connection.query(
            'INSERT INTO api_keys (user_id, api_key_hash, api_key_value, expiry_date) VALUES (?, ?, ?, ?)',
            [userId, apiKeyHash, apiKey, expiryDate]
        );

        await connection.commit(); // Commit transaksi

        // Beri respons balik dengan key yang baru digenerate
        res.status(201).json({ 
            success: true, 
            message: 'User dan API Key berhasil disimpan.', 
            apiKey: apiKey // NOTE: Di sini kita mengirimkan key mentah ke client untuk ditampilkan
        });

    } catch (error) {
        await connection.rollback(); // Jika ada error, batalkan transaksi
        if (error.code === 'ER_DUP_ENTRY') {
             return res.status(409).json({ success: false, message: 'Email sudah terdaftar.' });
        }
        console.error('Error saving user and key:', error);
        res.status(500).json({ success: false, message: 'Server error saat menyimpan data.' });
    } finally {
        if (connection) connection.release();
    }
};

// --- 2. AMBIL DATA DASHBOARD (Rute /api/admin/dashboard) ---
exports.getDashboardData = async (req, res) => {
    // Perhatikan: Rute ini dilindungi oleh verifyToken, jadi hanya admin yang bisa mengakses
    
    try {
        // Query untuk menggabungkan data user dan API key
        const query = `
            SELECT 
                u.user_id, 
                u.first_name, 
                u.email, 
                u.user_since,
                k.api_key_value, 
                k.status, 
                k.expiry_date
            FROM users u
            JOIN api_keys k ON u.user_id = k.user_id
            ORDER BY u.user_id DESC;
        `;
        
        const [results] = await pool.promise().query(query);

        res.json({ success: true, data: results });

    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).json({ success: false, message: 'Gagal mengambil data dashboard.' });
    }
};