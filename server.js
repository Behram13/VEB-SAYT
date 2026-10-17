
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const ROOT = __dirname;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s]).{8,64}$/;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
    console.error("DATABASE_URL və SESSION_SECRET təyin edilməlidir.");
    process.exit(1);
}
if (IS_PRODUCTION && (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD_HASH)) {
    console.error("ADMIN_USERNAME və ADMIN_PASSWORD_HASH təyin edilməlidir.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    connectionTimeoutMillis: 10000
});

app.set("trust proxy", IS_PRODUCTION ? 1 : false);
app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

function jsonError(res, status, message) {
    return res.status(status).json({ error: message });
}
function asyncRoute(fn) {
    return function (req, res, next) {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}
function getClientIp(req) {
    return req.ip || req.socket.remoteAddress || null;
}
function cleanFin(fin) {
    return typeof fin === "string" ? fin.trim().toUpperCase() : "";
}
function validFin(fin) {
    return /^[A-Z0-9]{7}$/.test(fin);
}
function validPassword(password) {
    return typeof password === "string" && PASSWORD_REGEX.test(password);
}
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return jsonError(res, 401, "Əvvəlcə hesabınıza daxil olun.");
    }
    next();
}
function requireAdmin(req, res, next) {
    if (!req.session.isAdmin) {
        return jsonError(res, 403, "Administrator girişi tələb olunur.");
    }
    next();
}
function adminPage(req, res, next) {
    if (!req.session.isAdmin) {
        return res.redirect("/admin-login");
    }
    next();
}
function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate(error => error ? reject(error) : resolve());
    });
}
function saveSession(req) {
    return new Promise((resolve, reject) => {
        req.session.save(error => error ? reject(error) : resolve());
    });
}
function destroySession(req) {
    return new Promise((resolve, reject) => {
        req.session.destroy(error => error ? reject(error) : resolve());
    });
}
function safeNumber(value) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number > 0 ? number : null;
}

app.use(session({
    store: new PgSession({
        pool: pool,
        tableName: "session",
        createTableIfMissing: true
    }),
    name: "klinika.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: "lax",
        maxAge: 60 * 60 * 1000
    }
}));

// Cross-origin form submissions are rejected.
app.use((req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
    }
    const origin = req.get("origin");
    if (!origin) {
        return next();
    }
    try {
        const originHost = new URL(origin).host;
        if (originHost !== req.get("host")) {
            return jsonError(res, 403, "Sorğu mənbəyinə icazə verilmir.");
        }
    } catch {
        return jsonError(res, 403, "Yanlış sorğu mənbəyi.");
    }
    next();
});

async function securityLog({
    fin = null,
    eventType,
    result,
    details = null,
    failedAttempts = 0,
    lockedUntil = null,
    ipAddress = null
}) {
    try {
        await pool.query(
            `INSERT INTO security_logs
            (fin, event_type, result, details, failed_attempts, locked_until, ip_address)
            VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [fin, eventType, result, details, failedAttempts, lockedUntil, ipAddress]
        );
    } catch (error) {
        console.error("Log yazılmadı:", error.message);
    }
}

async function createTables() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            fin VARCHAR(7) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMPTZ
        );
        CREATE TABLE IF NOT EXISTS appointments (
            id SERIAL PRIMARY KEY,
            ad VARCHAR(100),
            soyad VARCHAR(100),
            telefon VARCHAR(20),
            hekim VARCHAR(100),
            tarix DATE,
            saat TIME
        );
        CREATE TABLE IF NOT EXISTS security_logs (
            id BIGSERIAL PRIMARY KEY,
            fin VARCHAR(7),
            event_type VARCHAR(60) NOT NULL,
            result VARCHAR(20) NOT NULL,
            details TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMPTZ,
            ip_address TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
    `);
    await pool.query(`
        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
        ALTER TABLE security_logs
            ADD COLUMN IF NOT EXISTS details TEXT;
        ALTER TABLE security_logs
            ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0;
        ALTER TABLE security_logs
            ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
        ALTER TABLE security_logs
            ADD COLUMN IF NOT EXISTS ip_address TEXT;
    `);
    console.log("Verilənlər bazası cədvəlləri hazırdır.");
}

// Public site assets: only the actual frontend files are exposed.
const publicFiles = [
    "index.html", "style.css", "script.js",
    "admin.css", "admin.js",
    "users-admin.css", "users-admin.js",
    "logs-admin.css", "logs-admin.js"
];
for (const filename of publicFiles) {
    app.get("/" + filename, (req, res) => {
        res.sendFile(path.join(ROOT, filename));
    });
}
app.get("/", (req, res) => {
    res.sendFile(path.join(ROOT, "index.html"));
});
app.get("/health", asyncRoute(async (req, res) => {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
}));

// Registration
app.post("/register", asyncRoute(async (req, res) => {
    const fin = cleanFin(req.body.fin);
    const password = req.body.password;

    if (!validFin(fin)) {
        return jsonError(res, 400, "FİN kod 7 hərf və rəqəmdən ibarət olmalıdır.");
    }
    if (!validPassword(password)) {
        return jsonError(res, 400, "Parol 8-64 simvol olmalı, böyük və kiçik hərf, rəqəm və xüsusi simvol içərməlidir.");
    }
    const passwordHash = await bcrypt.hash(password, 12);
    try {
        await pool.query(
            "INSERT INTO users (fin, password_hash) VALUES ($1,$2)",
            [fin, passwordHash]
        );
    } catch (error) {
        if (error.code === "23505") {
            await securityLog({
                fin, eventType: "REGISTER_FAILED", result: "FAILED",
                details: "FİN artıq mövcuddur.", ipAddress: getClientIp(req)
            });
            return jsonError(res, 409, "Bu FİN ilə hesab artıq mövcuddur. Giriş edin.");
        }
        throw error;
    }
    await securityLog({
        fin, eventType: "REGISTER_SUCCESS", result: "SUCCESS",
        details: "İstifadəçi qeydiyyatdan keçdi.", ipAddress: getClientIp(req)
    });
    return res.status(201).json({
        message: "Qeydiyyat uğurla tamamlandı.", fin
    });
}));

// Login with atomic failed-attempt tracking
app.post("/login", asyncRoute(async (req, res) => {
    const fin = cleanFin(req.body.fin);
    const password = req.body.password;
    if (!validFin(fin) || typeof password !== "string" || password.length > 128) {
        return jsonError(res, 400, "FİN və parolu düzgün daxil edin.");
    }
    const client = await pool.connect();
    let outcome;
    try {
        await client.query("BEGIN");
        const result = await client.query(
            "SELECT * FROM users WHERE fin=$1 FOR UPDATE", [fin]
        );
        if (!result.rows.length) {
            outcome = { status: 404, error: "Bu FİN ilə hesab yoxdur. Qeydiyyatdan keçin.", event: "LOGIN_FAILED", attempts: 0 };
        } else {
            const user = result.rows[0];
            let attempts = Number(user.failed_attempts || 0);
            const locked = user.locked_until && new Date(user.locked_until) > new Date();
            if (locked) {
                const minutes = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
                outcome = {
                    status: 423,
                    error: `Hesab bloklanıb. Təxminən ${Math.max(1, minutes)} dəqiqə sonra cəhd edin.`,
                    event: "LOGIN_BLOCKED", attempts,
                    lockedUntil: user.locked_until
                };
            } else {
                if (user.locked_until) attempts = 0;
                const correct = await bcrypt.compare(password, user.password_hash);
                if (!correct) {
                    attempts++;
                    const shouldLock = attempts >= 5;
                    const updated = await client.query(
                        `UPDATE users SET failed_attempts=$1,
                        locked_until=CASE WHEN $2 THEN NOW() + INTERVAL '10 minutes' ELSE NULL END
                        WHERE id=$3 RETURNING locked_until`,
                        [Math.min(attempts, 5), shouldLock, user.id]
                    );
                    outcome = {
                        status: shouldLock ? 423 : 401,
                        error: shouldLock
                            ? "Parol 5 dəfə səhv daxil edildi. Hesab 10 dəqiqəlik bloklandı."
                            : `Parol yanlışdır. Qalan cəhd sayı: ${5 - attempts}`,
                        event: "LOGIN_FAILED", attempts: Math.min(attempts, 5),
                        lockedUntil: updated.rows[0].locked_until,
                        blocked: shouldLock
                    };
                } else {
                    await client.query(
                        "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=$1",
                        [user.id]
                    );
                    outcome = { success: true, userId: user.id, fin: user.fin };
                }
            }
        }
        await client.query("COMMIT");
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
    if (!outcome.success) {
        await securityLog({
            fin, eventType: outcome.event, result: "FAILED",
            details: outcome.error, failedAttempts: outcome.attempts,
            lockedUntil: outcome.lockedUntil || null, ipAddress: getClientIp(req)
        });
        if (outcome.blocked) {
            await securityLog({
                fin, eventType: "ACCOUNT_LOCKED", result: "FAILED",
                details: "5 səhv girişdən sonra 10 dəqiqəlik bloklanma.",
                failedAttempts: 5, lockedUntil: outcome.lockedUntil,
                ipAddress: getClientIp(req)
            });
        }
        return jsonError(res, outcome.status, outcome.error);
    }
    await regenerateSession(req);
    req.session.userId = outcome.userId;
    req.session.fin = outcome.fin;
    await saveSession(req);
    await securityLog({
        fin, eventType: "LOGIN_SUCCESS", result: "SUCCESS",
        details: "Uğurlu giriş.", ipAddress: getClientIp(req)
    });
    res.json({ message: "Giriş uğurludur.", fin });
}));

app.get("/me", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ loggedIn: false });
    }
    res.json({
        loggedIn: true,
        userId: req.session.userId,
        fin: req.session.fin
    });
});

// Change password
app.post("/change-password", requireLogin, asyncRoute(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (typeof currentPassword !== "string" || !validPassword(newPassword)) {
        return jsonError(res, 400, "Yeni parol qaydalara uyğun deyil.");
    }
    const result = await pool.query(
        "SELECT id,fin,password_hash FROM users WHERE id=$1",
        [req.session.userId]
    );
    if (!result.rows.length) {
        return jsonError(res, 404, "İstifadəçi tapılmadı.");
    }
    const user = result.rows[0];
    if (!(await bcrypt.compare(currentPassword, user.password_hash))) {
        await securityLog({
            fin: user.fin, eventType: "PASSWORD_CHANGE_FAILED",
            result: "FAILED", details: "Cari parol səhvdir.",
            ipAddress: getClientIp(req)
        });
        return jsonError(res, 401, "Cari parol yanlışdır.");
    }
    if (await bcrypt.compare(newPassword, user.password_hash)) {
        return jsonError(res, 400, "Yeni parol cari parolla eyni ola bilməz.");
    }
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query(
        "UPDATE users SET password_hash=$1, failed_attempts=0, locked_until=NULL WHERE id=$2",
        [hash, user.id]
    );
    await securityLog({
        fin: user.fin, eventType: "PASSWORD_CHANGED",
        result: "SUCCESS", details: "Parol dəyişdirildi.",
        ipAddress: getClientIp(req)
    });
    res.json({ message: "Parol uğurla dəyişdirildi." });
}));

app.post("/logout", asyncRoute(async (req, res) => {
    const fin = req.session.fin || null;
    await destroySession(req);
    res.clearCookie("klinika.sid");
    if (fin) {
        await securityLog({
            fin, eventType: "LOGOUT_SUCCESS", result: "SUCCESS",
            details: "İstifadəçi çıxış etdi.", ipAddress: getClientIp(req)
        });
    }
    res.json({ message: "Hesabdan uğurla çıxış edildi." });
}));

// Create appointment
app.post("/novbe", requireLogin, asyncRoute(async (req, res) => {
    const { ad, soyad, telefon, hekim, tarix, saat } = req.body;
    if (![ad, soyad, telefon, hekim, tarix, saat].every(v => typeof v === "string" && v.trim())) {
        return jsonError(res, 400, "Bütün xanaları doldurun.");
    }
    if (ad.length > 100 || soyad.length > 100 || telefon.length > 20 || hekim.length > 100 ||
        !/^\d{4}-\d{2}-\d{2}$/.test(tarix) || !/^\d{2}:\d{2}$/.test(saat)) {
        return jsonError(res, 400, "Növbə məlumatları düzgün deyil.");
    }
    const result = await pool.query(
        `INSERT INTO appointments (ad,soyad,telefon,hekim,tarix,saat)
        VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
        [ad.trim(), soyad.trim(), telefon.trim(), hekim.trim(), tarix, saat]
    );
    await securityLog({
        fin: req.session.fin,
        eventType: "APPOINTMENT_CREATED",
        result: "SUCCESS",
        details: `Növbə #${result.rows[0].id}: ${hekim}, ${tarix} ${saat}`,
        ipAddress: getClientIp(req)
    });
    res.json({ message: "Növbə uğurla qeydə alındı." });
}));

// Administrator login page
app.get("/admin-login", (req, res) => {
    if (req.session.isAdmin) return res.redirect("/admin.html");
    res.type("html").send(`<!DOCTYPE html>
<html lang="az">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Administrator girişi</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#eef5fc;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;color:#24344c}
main{background:#fff;width:min(420px,92vw);padding:36px;border-radius:18px;box-shadow:0 14px 45px #1233}
h1{text-align:center;color:#0d47a1;font-size:25px}
label{display:block;font-weight:bold;margin-top:18px;margin-bottom:7px}
input{width:100%;padding:13px;border:1px solid #cbd5e1;border-radius:8px;font:inherit}
button{width:100%;padding:13px;margin-top:22px;background:#1565c0;color:white;border:0;border-radius:8px;font-weight:bold;cursor:pointer}
#error{color:#c62828;text-align:center}
</style>
</head>
<body>
<main>
<h1>Administrator girişi</h1>
<form id="form">
<label for="username">İstifadəçi adı</label>
<input id="username" autocomplete="username" required>
<label for="password">Parol</label>
<input id="password" type="password" autocomplete="current-password" required>
<button type="submit">Daxil ol</button>
<p id="error" role="alert"></p>
</form>
</main>
<script>
document.getElementById("form").addEventListener("submit",async e=>{
e.preventDefault();
const error=document.getElementById("error");
error.textContent="";
try{
const response=await fetch("/admin-login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({
username:document.getElementById("username").value,
password:document.getElementById("password").value
})});
const data=await response.json();
if(!response.ok){error.textContent=data.error||"Giriş alınmadı.";return;}
window.location.href="/admin.html";
}catch{error.textContent="Serverlə əlaqə alınmadı.";}
});
</script>
</body>
</html>`);
});

// Administrator login with a delay on incorrect credentials
const adminAttempts = new Map();
app.post("/admin-login", asyncRoute(async (req, res) => {
    const ip = getClientIp(req);
    const now = Date.now();
    const attempts = adminAttempts.get(ip) || { count: 0, until: 0 };
    if (attempts.until > now) {
        return jsonError(res, 429, "Çox sayda cəhd. 15 dəqiqə sonra yenidən yoxlayın.");
    }
    const username = req.body.username;
    const password = req.body.password;
    const correctUsername = typeof username === "string" &&
        username === process.env.ADMIN_USERNAME;
    const correctPassword = typeof password === "string" && password.length <= 128 &&
        await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH || "$2b$12$invalidhash");
    if (!correctUsername || !correctPassword) {
        const count = attempts.count + 1;
        adminAttempts.set(ip, {
            count,
            until: count >= 5 ? now + 15 * 60 * 1000 : 0
        });
        return jsonError(res, 401, "Administrator adı və ya parolu səhvdir.");
    }
    adminAttempts.delete(ip);
    await regenerateSession(req);
    req.session.isAdmin = true;
    await saveSession(req);
    res.json({ message: "Administrator girişi uğurludur." });
}));
app.post("/admin-logout", requireAdmin, asyncRoute(async (req, res) => {
    await destroySession(req);
    res.clearCookie("klinika.sid");
    res.json({ message: "Administrator çıxış etdi." });
}));

// Protected admin pages
app.get("/admin.html", adminPage, (req, res) => {
    res.sendFile(path.join(ROOT, "admin.html"));
});
app.get("/users-admin.html", adminPage, (req, res) => {
    res.sendFile(path.join(ROOT, "users-admin.html"));
});
app.get("/logs-admin.html", adminPage, (req, res) => {
    res.sendFile(path.join(ROOT, "logs-admin.html"));
});

// Protected admin APIs
app.get("/appointments", requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query("SELECT * FROM appointments ORDER BY id DESC LIMIT 1000");
    res.json(result.rows);
}));
app.delete("/appointments/:id", requireAdmin, asyncRoute(async (req, res) => {
    const id = safeNumber(req.params.id);
    if (!id) return jsonError(res, 400, "Yanlış növbə ID-si.");
    const result = await pool.query("DELETE FROM appointments WHERE id=$1 RETURNING id", [id]);
    if (!result.rowCount) return jsonError(res, 404, "Növbə tapılmadı.");
    await securityLog({
        eventType: "APPOINTMENT_DELETED",
        result: "SUCCESS",
        details: `Administrator növbə #${id} sildi.`,
        ipAddress: getClientIp(req)
    });
    res.json({ message: "Növbə silindi." });
}));
app.get("/users", requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(
        `SELECT id,fin,password_hash,created_at,failed_attempts,locked_until
        FROM users ORDER BY id DESC LIMIT 1000`
    );
    res.json(result.rows);
}));
app.post("/users/:id/verify-password", requireAdmin, asyncRoute(async (req, res) => {
    const id = safeNumber(req.params.id);
    const password = req.body.password;
    if (!id || typeof password !== "string" || password.length > 128) {
        return jsonError(res, 400, "Düzgün parol daxil edin.");
    }
    const result = await pool.query(
        "SELECT fin,password_hash FROM users WHERE id=$1", [id]
    );
    if (!result.rows.length) return jsonError(res, 404, "İstifadəçi tapılmadı.");
    const matches = await bcrypt.compare(password, result.rows[0].password_hash);
    res.json({ matches, fin: result.rows[0].fin });
}));
app.get("/security-logs", requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(
        `SELECT id,fin,event_type,result,details,failed_attempts,
        locked_until,ip_address,created_at
        FROM security_logs ORDER BY id DESC LIMIT 2000`
    );
    res.json(result.rows);
}));

app.use((req, res) => jsonError(res, 404, "Səhifə tapılmadı."));
app.use((error, req, res, next) => {
    console.error("Server xətası:", error);
    jsonError(res, 500, "Server xətası baş verdi.");
});

async function startServer() {
    try {
        await pool.query("SELECT 1");
        console.log("PostgreSQL bağlantısı uğurludur.");
        await createTables();
        app.listen(PORT, "0.0.0.0", () => {
            console.log("================================");
            console.log("Sağlam Həyat Klinikası");
            console.log(`Server portu: ${PORT}`);
            console.log("Admin girişi: /admin-login");
            console.log("Növbələr: /admin.html");
            console.log("İstifadəçilər: /users-admin.html");
            console.log("Loglar: /logs-admin.html");
            console.log("================================");
        });
    } catch (error) {
        console.error("Server başladılmadı:", error);
        process.exit(1);
    }
}
startServer();
