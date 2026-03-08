const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const fs = require('fs').promises;
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const VERIFICATION_TTL_MS = 10 * 60 * 1000;
const MAX_VERIFY_ATTEMPTS = 5;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost';

app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
app.use(express.json());

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: "Too many requests. Rate limit active." }
});
app.use('/api/', apiLimiter);

const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Authentication required." });
    }
    try {
        const token = authHeader.split(' ')[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token." });
    }
};

const checkRole = (req, res, next) => {
    const highRiskModules = ['getsystem', 'hashdump'];
    if (highRiskModules.includes(req.body.attackType) && req.user.role !== 'Admin') {
        return res.status(403).json({ error: "Administrative clearance required for this module." });
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ error: "Admin access required." });
    }
    next();
};

function validatePassword(password) {
    if (!password || password.length < 8) return "Password must be at least 8 characters.";
    if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter.";
    if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter.";
    if (!/[^a-zA-Z0-9]/.test(password)) return "Password must contain at least one special character.";
    return null;
}

function validateUsername(username) {
    if (!username || username.length < 3) return "Username must be at least 3 characters.";
    if (username.length > 30) return "Username must be 30 characters or fewer.";
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) return "Username may only contain letters, numbers, hyphens, and underscores.";
    return null;
}

const pool = new Pool({
    host: process.env.DB_HOST || 'database',
    user: process.env.DB_USER || 'msf_admin',
    password: process.env.DB_PASSWORD || 'changeme',
    database: process.env.DB_NAME || 'metasploit_db'
});

const initDb = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS scan_history (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) DEFAULT 'Unknown',
                action VARCHAR(255) NOT NULL,
                target VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        const userCheck = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCheck.rows[0].count) === 0) {
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
            const salt = await bcrypt.genSalt(12);
            const hash = await bcrypt.hash(defaultPassword, salt);
            await pool.query(
                'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)',
                ['admin', 'admin@system.local', hash, 'Admin']
            );
            console.log("[SYSTEM] Default admin created. Change the password immediately.");
        }
        console.log("[SYSTEM] Database verified and ready.");
    } catch (err) {
        console.error("[CRITICAL] Database Init Error:", err.message);
    }
};
initDb();

app.get('/api/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', uptime: process.uptime() });
    } catch {
        res.status(503).json({ status: 'unavailable' });
    }
});

const pendingVerifications = new Map();
const activeUsers = new Map();

const verificationCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [email, data] of pendingVerifications) {
        if (now - data.createdAt > VERIFICATION_TTL_MS) {
            pendingVerifications.delete(email);
        }
    }
}, 5 * 60 * 1000);
verificationCleanupTimer.unref();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.MAIL_USER || '',
        pass: process.env.MAIL_PASS || ''
    }
});

app.post('/api/register/init', async (req, res) => {
    const { username, email, password } = req.body;
    const role = 'SOC Analyst';

    if (!username || !email || !password) {
        return res.status(400).json({ error: "All fields are required." });
    }

    const usernameError = validateUsername(username);
    if (usernameError) return res.status(400).json({ error: usernameError });

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ error: passwordError });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: "Invalid email format." });
    }

    try {
        const check = await pool.query(
            'SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]
        );
        if (check.rows.length > 0) {
            return res.status(400).json({ error: "Username or email already exists." });
        }

        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        pendingVerifications.set(email, {
            username, email, hashedPassword, role,
            code: verificationCode,
            createdAt: Date.now(),
            attempts: 0
        });

        const mailOptions = {
            from: `"MSF Platform Security" <${process.env.MAIL_USER || 'no-reply@msfcloud.com'}>`,
            to: email,
            subject: 'MSF Platform - Your Verification Code',
            text: `Hello ${username},\n\nYour verification code is: ${verificationCode}\n\nThis code expires in 10 minutes.`
        };

        try {
            await transporter.sendMail(mailOptions);
            return res.json({ message: "Verification code sent to your email." });
        } catch {
            console.log(`[FALLBACK] Verification code for ${email}: ${verificationCode}`);
            return res.json({ message: "Code generated. Check server logs if email delivery fails." });
        }
    } catch (e) {
        res.status(500).json({ error: "Internal server error." });
    }
});

app.post('/api/register/verify', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ error: "Email and code are required." });
    }

    const pending = pendingVerifications.get(email);
    if (!pending) {
        return res.status(400).json({ error: "No pending verification for this email." });
    }

    if (Date.now() - pending.createdAt > VERIFICATION_TTL_MS) {
        pendingVerifications.delete(email);
        return res.status(400).json({ error: "Verification code expired. Please register again." });
    }

    pending.attempts += 1;
    if (pending.attempts > MAX_VERIFY_ATTEMPTS) {
        pendingVerifications.delete(email);
        return res.status(429).json({ error: "Too many attempts. Please register again." });
    }

    if (pending.code !== code) {
        return res.status(400).json({ error: "Invalid verification code." });
    }

    try {
        await pool.query(
            'INSERT INTO users(username, email, password, role) VALUES($1, $2, $3, $4)',
            [pending.username, pending.email, pending.hashedPassword, pending.role]
        );
        pendingVerifications.delete(email);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Database error." });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required." });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const token = jwt.sign(
            { username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        activeUsers.set(username, Date.now());
        res.json({ success: true, username: user.username, role: user.role, token });
    } catch (e) {
        res.status(500).json({ error: "Authentication service error." });
    }
});

app.get('/api/users/count', async (req, res) => {
    try {
        const result = await pool.query('SELECT COUNT(*) FROM users');
        res.json({ count: result.rows[0].count });
    } catch (e) {
        res.status(500).json({ count: 0 });
    }
});

app.post('/api/heartbeat', (req, res) => {
    const { username } = req.body;
    if (username) activeUsers.set(username, Date.now());

    const now = Date.now();
    for (const [user, lastSeen] of activeUsers) {
        if (now - lastSeen > 60000) activeUsers.delete(user);
    }

    res.json({ activeCount: activeUsers.size });
});

const simulatedOutputs = {
    'keyscan': () => `meterpreter > keyscan_start\n[*] Starting the keystroke sniffer...\n[*] Capturing data packets...\n[CAPTURED]: admin_portal / SecretAdminPass1!`,
    'screenshot': (target) => `meterpreter > screenshot\n[*] Taking screenshot of desktop...\n[+] Captured screen from ${target}\n[+] Saved to /app/loot/intel_capture_${Date.now()}.jpg`,
    'webcam': () => `meterpreter > webcam_snap\n[*] Initializing camera...\n[+] Image saved to /app/loot/cam_snap_${Date.now()}.jpg`,
    'mic': () => `meterpreter > record_mic -d 5\n[*] Recording audio (5s)...\n[+] Audio saved to /app/loot/audio_${Date.now()}.wav`,
    'screenshare': () => `meterpreter > screenshare\n[*] Starting live stream...\n[+] Stream active at http://127.0.0.1:8080`,
    'getsystem': () => `meterpreter > getsystem\n[*] Attempting privilege escalation...\n[+] Success: Obtained NT AUTHORITY\\SYSTEM via Named Pipe Impersonation.`,
    'hashdump': () => `meterpreter > hashdump\n[*] Extracting local SAM hashes...\nAdministrator:500:aad3b435b...:31d6cfe0d...\nGuest:501:aad3b435b...:31d6cfe0d...`,
    'persistence': () => `meterpreter > run persistence -U -i 5\n[*] Installing to autorun...\n[+] Installed persistent backdoor (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)`,
    'download': () => `meterpreter > download c:\\users\\admin\\documents\\secrets.pdf\n[*] Downloading file...\n[+] Downloaded 1.2MB to /app/loot/secrets_${Date.now()}.pdf`,
    'timestomp': () => `meterpreter > timestomp secrets.pdf -v\n[*] Modifying MACE file attributes...\n[+] Success: File timestamps modified (Anti-Forensics active).`,
    'web_scan': (target) => `[*] AI Scanner initiating on ${target}...\n[+] Technology Detected: Linux Ubuntu / Nginx 1.24\n[!] CRITICAL VULNERABILITY: WordPress 6.4.1 (CVE-2023-22515)\n[*] Full report cached in memory.`,
    'reverse_shell': (target) => `[*] Encrypting payload stage...\n[*] Sending stage to ${target}:4444\n[+] Meterpreter session 1 opened (Local -> Remote).`,
    'payload': () => `[*] msfvenom generating payload...\n[*] Platform: windows | Arch: x64\n[*] Encoder: x64/xor | Iterations: 5\n[+] Payload size: 510 bytes\n[+] Saved as /app/loot/payload_${Date.now()}.exe`
};

app.get('/api/history', authenticate, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM scan_history ORDER BY id DESC LIMIT 50');
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: "Audit logs unreachable." });
    }
});

app.post('/api/attack', authenticate, checkRole, async (req, res) => {
    const { attackType, targetIp } = req.body;
    const username = req.user.username;

    if (!attackType) {
        return res.status(400).json({ error: "attackType is required." });
    }

    const allowedAttackTypes = Object.keys(simulatedOutputs);
    if (!allowedAttackTypes.includes(attackType)) {
        return res.status(400).json({ error: "Unknown attack module." });
    }

    console.log(`[!] User '${username}' executed module '${attackType}' on target [${targetIp || 'Internal Node'}]`);

    const lootDir = path.join(__dirname, 'loot');
    if (['screenshot', 'webcam', 'mic', 'download', 'hashdump'].includes(attackType)) {
        const ext = attackType === 'screenshot' || attackType === 'webcam' ? 'jpg' :
                    attackType === 'mic' ? 'wav' :
                    attackType === 'download' ? 'pdf' : 'txt';
        const fileContent = `[Simulated Captured Data for ${attackType} module. Timestamp: ${new Date().toISOString()}]`;
        try {
            await fs.mkdir(lootDir, { recursive: true });
            await fs.writeFile(path.join(lootDir, `${attackType}_${Date.now()}.${ext}`), fileContent);
            console.log(`[+] File saved to loot directory.`);
        } catch (err) {
            console.error(`[!] Failed to write loot file: ${err.message}`);
        }
    }

    const output = simulatedOutputs[attackType](targetIp || '10.0.0.1');

    try {
        await pool.query(
            'INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)',
            [username, attackType, targetIp || 'Internal Node', 'Success']
        );
    } catch (e) {
        console.error("[LOG ERROR] Failed to record transaction.");
    }

    res.json({ terminalOutput: output });
});

// Admin: list all users
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, email, role, created_at FROM users ORDER BY id ASC'
        );
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch users." });
    }
});

// Admin: change user role
app.put('/api/admin/users/:id/role', authenticate, requireAdmin, async (req, res) => {
    const { role } = req.body;
    const userId = parseInt(req.params.id);

    const allowedRoles = ['SOC Analyst', 'Admin'];
    if (!role || !allowedRoles.includes(role)) {
        return res.status(400).json({ error: "Invalid role. Allowed: SOC Analyst, Admin." });
    }
    if (isNaN(userId)) {
        return res.status(400).json({ error: "Invalid user ID." });
    }

    try {
        const check = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        if (check.rows[0].username === req.user.username) {
            return res.status(400).json({ error: "Cannot change your own role." });
        }
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, userId]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Failed to update role." });
    }
});

// Admin: reset user password
app.put('/api/admin/users/:id/password', authenticate, requireAdmin, async (req, res) => {
    const { newPassword } = req.body;
    const userId = parseInt(req.params.id);

    if (isNaN(userId)) {
        return res.status(400).json({ error: "Invalid user ID." });
    }

    const pwError = validatePassword(newPassword);
    if (pwError) return res.status(400).json({ error: pwError });

    try {
        const check = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(newPassword, salt);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, userId]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Failed to reset password." });
    }
});

// Admin: delete user
app.delete('/api/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.id);

    if (isNaN(userId)) {
        return res.status(400).json({ error: "Invalid user ID." });
    }

    try {
        const check = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
        if (check.rows.length === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        if (check.rows[0].username === req.user.username) {
            return res.status(400).json({ error: "Cannot delete your own account." });
        }
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Failed to delete user." });
    }
});

if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, () => console.log(`[SYSTEM] MSF Control Node Active on Port ${PORT}`));

    const shutdown = async (signal) => {
        console.log(`\n[SYSTEM] ${signal} received — shutting down gracefully...`);
        server.close(() => {
            pool.end().then(() => {
                console.log('[SYSTEM] Database pool closed.');
                process.exit(0);
            });
        });
        setTimeout(() => process.exit(1), 10000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = app;
