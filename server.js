const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "klinika-secret-key-2026-change-later",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            maxAge: 1000 * 60 * 60
        }
    })
);

const pool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "klinika_db",
    password: "1234",
    port: 5432
});

pool.connect()
    .then(function (client) {
        console.log("PostgreSQL bağlantısı uğurludur.");
        client.release();
    })
    .catch(function (error) {
        console.error("PostgreSQL bağlantı xətası:", error);
    });

function getClientIp(req) {
    const forwarded = req.headers["x-forwarded-for"];

    if (forwarded) {
        return forwarded.split(",")[0].trim();
    }

    return req.socket.remoteAddress || req.ip || null;
}

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
            `
            INSERT INTO security_logs
            (
                fin,
                event_type,
                result,
                details,
                failed_attempts,
                locked_until,
                ip_address
            )
            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7
            )
            `,
            [
                fin,
                eventType,
                result,
                details,
                failedAttempts,
                lockedUntil,
                ipAddress
            ]
        );
    } catch (error) {
        console.error("Security log yazılmadı:", error);
    }
}

function parolGucludur(password) {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s]).{8,64}$/;
    return regex.test(password);
}

function loginTelebOlunur(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "Əvvəlcə hesabınıza daxil olun."
        });
    }

    next();
}

app.get("/", function (req, res) {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/register", async function (req, res) {
    const fin = req.body.fin;
    const password = req.body.password;

    if (!fin || !password) {
        return res.status(400).json({
            error: "FİN və parol daxil edilməlidir."
        });
    }

    const cleanFin = fin.trim().toUpperCase();

    if (!/^[A-Z0-9]{7}$/.test(cleanFin)) {
        return res.status(400).json({
            error: "FİN kod 7 hərf və rəqəmdən ibarət olmalıdır."
        });
    }

    if (!parolGucludur(password)) {
        return res.status(400).json({
            error: "Parol minimum 8 simvol olmalı, böyük hərf, kiçik hərf, rəqəm və xüsusi simvol içərməlidir."
        });
    }

    try {
        const existing = await pool.query(
            `
            SELECT id
            FROM users
            WHERE fin = $1
            `,
            [cleanFin]
        );

        if (existing.rows.length > 0) {
            await securityLog({
                fin: cleanFin,
                eventType: "REGISTER_FAILED",
                result: "FAILED",
                details: "Bu FİN ilə hesab artıq mövcuddur.",
                ipAddress: getClientIp(req)
            });

            return res.status(409).json({
                error: "Bu FİN ilə artıq hesab mövcuddur. Giriş edin."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `
            INSERT INTO users
            (
                fin,
                password_hash
            )
            VALUES
            (
                $1,
                $2
            )
            RETURNING
                id,
                fin,
                created_at
            `,
            [
                cleanFin,
                passwordHash
            ]
        );

        await securityLog({
            fin: result.rows[0].fin,
            eventType: "REGISTER_SUCCESS",
            result: "SUCCESS",
            details: "Yeni istifadəçi qeydiyyatdan keçdi.",
            ipAddress: getClientIp(req)
        });

        console.log("REGISTER_SUCCESS:", result.rows[0].fin);

        return res.status(201).json({
            message: "Qeydiyyat uğurla tamamlandı.",
            fin: result.rows[0].fin
        });
    } catch (error) {
        console.error("Register xətası:", error);

        return res.status(500).json({
            error: "Qeydiyyat zamanı server xətası baş verdi."
        });
    }
});

app.post("/login", async function (req, res) {
    const fin = req.body.fin;
    const password = req.body.password;

    if (!fin || !password) {
        return res.status(400).json({
            error: "FİN və parol daxil edilməlidir."
        });
    }

    const cleanFin = fin.trim().toUpperCase();

    try {
        const result = await pool.query(
            `
            SELECT
                id,
                fin,
                password_hash,
                failed_attempts,
                locked_until
            FROM users
            WHERE fin = $1
            `,
            [cleanFin]
        );

        if (result.rows.length === 0) {
            await securityLog({
                fin: cleanFin,
                eventType: "LOGIN_FAILED",
                result: "FAILED",
                details: "Bu FİN ilə hesab yoxdur.",
                failedAttempts: 0,
                ipAddress: getClientIp(req)
            });

            return res.status(404).json({
                error: "Bu FİN ilə hesab yoxdur. Qeydiyyatdan keçin."
            });
        }

        const user = result.rows[0];

        if (user.locked_until) {
            const lockedUntil = new Date(user.locked_until);
            const now = new Date();

            if (lockedUntil > now) {
                const remainingMs = lockedUntil.getTime() - now.getTime();
                const remainingMinutes = Math.max(
                    1,
                    Math.ceil(remainingMs / 60000)
                );

                await securityLog({
                    fin: user.fin,
                    eventType: "LOGIN_BLOCKED",
                    result: "FAILED",
                    details: "Bloklanmış hesabla giriş cəhdi edildi.",
                    failedAttempts: user.failed_attempts,
                    lockedUntil: user.locked_until,
                    ipAddress: getClientIp(req)
                });

                return res.status(423).json({
                    error:
                        "Hesab bloklanıb. Təxminən " +
                        remainingMinutes +
                        " dəqiqə sonra yenidən cəhd edin."
                });
            }

            await pool.query(
                `
                UPDATE users
                SET
                    failed_attempts = 0,
                    locked_until = NULL
                WHERE id = $1
                `,
                [user.id]
            );

            user.failed_attempts = 0;
            user.locked_until = null;
        }

        const correctPassword = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!correctPassword) {
            const attempts = Number(user.failed_attempts) + 1;

            await securityLog({
                fin: user.fin,
                eventType: "LOGIN_FAILED",
                result: "FAILED",
                details: "Səhv parol daxil edildi.",
                failedAttempts: attempts,
                ipAddress: getClientIp(req)
            });

            if (attempts >= 5) {
                const lockResult = await pool.query(
                    `
                    UPDATE users
                    SET
                        failed_attempts = 5,
                        locked_until =
                            CURRENT_TIMESTAMP + INTERVAL '10 minutes'
                    WHERE id = $1
                    RETURNING locked_until
                    `,
                    [user.id]
                );

                const lockedUntil = lockResult.rows[0].locked_until;

                await securityLog({
                    fin: user.fin,
                    eventType: "ACCOUNT_LOCKED",
                    result: "FAILED",
                    details: "5 uğursuz giriş cəhdindən sonra hesab 10 dəqiqəlik bloklandı.",
                    failedAttempts: 5,
                    lockedUntil: lockedUntil,
                    ipAddress: getClientIp(req)
                });

                console.log("ACCOUNT_LOCKED:", user.fin);

                return res.status(423).json({
                    error: "Parol 5 dəfə səhv daxil edildi. Hesab 10 dəqiqəlik bloklandı."
                });
            }

            await pool.query(
                `
                UPDATE users
                SET failed_attempts = $1
                WHERE id = $2
                `,
                [
                    attempts,
                    user.id
                ]
            );

            const remaining = 5 - attempts;

            console.log(
                "LOGIN_FAILED:",
                user.fin,
                "Attempt:",
                attempts
            );

            return res.status(401).json({
                error:
                    "Parol yanlışdır. Qalan cəhd sayı: " +
                    remaining
            });
        }

        await pool.query(
            `
            UPDATE users
            SET
                failed_attempts = 0,
                locked_until = NULL
            WHERE id = $1
            `,
            [user.id]
        );

        req.session.regenerate(function (error) {
            if (error) {
                return res.status(500).json({
                    error: "Session yaratmaq mümkün olmadı."
                });
            }

            req.session.userId = user.id;
            req.session.fin = user.fin;

            req.session.save(async function (error) {
                if (error) {
                    return res.status(500).json({
                        error: "Session yadda saxlanmadı."
                    });
                }

                await securityLog({
                    fin: user.fin,
                    eventType: "LOGIN_SUCCESS",
                    result: "SUCCESS",
                    details: "İstifadəçi sistemə uğurla daxil oldu.",
                    ipAddress: getClientIp(req)
                });

                console.log("LOGIN_SUCCESS:", user.fin);

                return res.json({
                    message: "Giriş uğurludur.",
                    fin: user.fin
                });
            });
        });
    } catch (error) {
        console.error("Login xətası:", error);

        return res.status(500).json({
            error: "Login zamanı server xətası baş verdi."
        });
    }
});

app.get("/me", function (req, res) {
    if (!req.session.userId) {
        return res.status(401).json({
            loggedIn: false
        });
    }

    return res.json({
        loggedIn: true,
        userId: req.session.userId,
        fin: req.session.fin
    });
});

app.post(
    "/change-password",
    loginTelebOlunur,
    async function (req, res) {
        const currentPassword = req.body.currentPassword;
        const newPassword = req.body.newPassword;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                error: "Cari və yeni parol daxil edilməlidir."
            });
        }

        if (!parolGucludur(newPassword)) {
            return res.status(400).json({
                error: "Yeni parol minimum 8 simvol olmalı, böyük hərf, kiçik hərf, rəqəm və xüsusi simvol içərməlidir."
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT
                    id,
                    fin,
                    password_hash
                FROM users
                WHERE id = $1
                `,
                [req.session.userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    error: "İstifadəçi tapılmadı."
                });
            }

            const user = result.rows[0];

            const currentCorrect = await bcrypt.compare(
                currentPassword,
                user.password_hash
            );

            if (!currentCorrect) {
                await securityLog({
                    fin: user.fin,
                    eventType: "PASSWORD_CHANGE_FAILED",
                    result: "FAILED",
                    details: "Cari parol səhv daxil edildi.",
                    ipAddress: getClientIp(req)
                });

                return res.status(401).json({
                    error: "Cari parol yanlışdır."
                });
            }

            const sameAsOld = await bcrypt.compare(
                newPassword,
                user.password_hash
            );

            if (sameAsOld) {
                return res.status(400).json({
                    error: "Yeni parol cari parolla eyni ola bilməz."
                });
            }

            const newPasswordHash = await bcrypt.hash(
                newPassword,
                12
            );

            await pool.query(
                `
                UPDATE users
                SET
                    password_hash = $1,
                    failed_attempts = 0,
                    locked_until = NULL
                WHERE id = $2
                `,
                [
                    newPasswordHash,
                    user.id
                ]
            );

            await securityLog({
                fin: user.fin,
                eventType: "PASSWORD_CHANGED",
                result: "SUCCESS",
                details: "İstifadəçi parolunu uğurla dəyişdi.",
                ipAddress: getClientIp(req)
            });

            console.log("PASSWORD_CHANGED:", user.fin);

            return res.json({
                message: "Parol uğurla dəyişdirildi."
            });
        } catch (error) {
            console.error("Change password xətası:", error);

            return res.status(500).json({
                error: "Parolu dəyişmək mümkün olmadı."
            });
        }
    }
);

app.post("/logout", function (req, res) {
    const fin = req.session.fin;
    const ipAddress = getClientIp(req);

    req.session.destroy(async function (error) {
        if (error) {
            return res.status(500).json({
                error: "Çıxış zamanı xəta baş verdi."
            });
        }

        res.clearCookie("connect.sid");

        await securityLog({
            fin: fin,
            eventType: "LOGOUT_SUCCESS",
            result: "SUCCESS",
            details: "İstifadəçi hesabdan çıxdı.",
            ipAddress: ipAddress
        });

        console.log("LOGOUT_SUCCESS:", fin);

        return res.json({
            message: "Hesabdan uğurla çıxış edildi."
        });
    });
});

app.post(
    "/novbe",
    loginTelebOlunur,
    async function (req, res) {
        const {
            ad,
            soyad,
            telefon,
            hekim,
            tarix,
            saat
        } = req.body;

        if (
            !ad ||
            !soyad ||
            !telefon ||
            !hekim ||
            !tarix ||
            !saat
        ) {
            return res.status(400).json({
                error: "Bütün xanaları doldurun."
            });
        }

        try {
            await pool.query(
                `
                INSERT INTO appointments
                (
                    ad,
                    soyad,
                    telefon,
                    hekim,
                    tarix,
                    saat
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    $6
                )
                `,
                [
                    ad,
                    soyad,
                    telefon,
                    hekim,
                    tarix,
                    saat
                ]
            );

            await securityLog({
                fin: req.session.fin,
                eventType: "APPOINTMENT_CREATED",
                result: "SUCCESS",
                details:
                    "Yeni növbə yaradıldı: " +
                    hekim +
                    ", " +
                    tarix +
                    " " +
                    saat,
                ipAddress: getClientIp(req)
            });

            console.log(
                "APPOINTMENT_CREATED:",
                req.session.fin
            );

            return res.json({
                message: "Növbə uğurla qeydə alındı."
            });
        } catch (error) {
            console.error("Növbə xətası:", error);

            return res.status(500).json({
                error: "Məlumat bazaya yazılmadı."
            });
        }
    }
);

app.get("/appointments", async function (req, res) {
    try {
        const result = await pool.query(
            `
            SELECT *
            FROM appointments
            ORDER BY id DESC
            `
        );

        return res.json(result.rows);
    } catch (error) {
        console.error("Appointments xətası:", error);

        return res.status(500).json({
            error: "Növbələri gətirmək mümkün olmadı."
        });
    }
});

app.delete(
    "/appointments/:id",
    async function (req, res) {
        try {
            await pool.query(
                `
                DELETE FROM appointments
                WHERE id = $1
                `,
                [req.params.id]
            );

            return res.json({
                message: "Növbə silindi."
            });
        } catch (error) {
            console.error(
                "Appointment delete xətası:",
                error
            );

            return res.status(500).json({
                error: "Növbə silinmədi."
            });
        }
    }
);

app.get("/users", async function (req, res) {
    try {
        const result = await pool.query(
            `
            SELECT
                id,
                fin,
                password_hash,
                created_at,
                failed_attempts,
                locked_until
            FROM users
            ORDER BY id DESC
            `
        );

        return res.json(result.rows);
    } catch (error) {
        console.error("Users gətirmə xətası:", error);

        return res.status(500).json({
            error: "İstifadəçiləri gətirmək mümkün olmadı."
        });
    }
});

app.post(
    "/users/:id/verify-password",
    async function (req, res) {
        const password = req.body.password;

        if (!password) {
            return res.status(400).json({
                error: "Parolu daxil edin."
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT
                    id,
                    fin,
                    password_hash
                FROM users
                WHERE id = $1
                `,
                [req.params.id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    error: "İstifadəçi tapılmadı."
                });
            }

            const user = result.rows[0];

            const matches = await bcrypt.compare(
                password,
                user.password_hash
            );

            return res.json({
                matches: matches,
                fin: user.fin
            });
        } catch (error) {
            console.error(
                "Password verify xətası:",
                error
            );

            return res.status(500).json({
                error: "Parolu yoxlamaq mümkün olmadı."
            });
        }
    }
);

app.get(
    "/security-logs",
    async function (req, res) {
        try {
            const result = await pool.query(
                `
                SELECT
                    id,
                    fin,
                    event_type,
                    result,
                    details,
                    failed_attempts,
                    locked_until,
                    ip_address,
                    created_at
                FROM security_logs
                ORDER BY id DESC
                `
            );

            return res.json(result.rows);
        } catch (error) {
            console.error(
                "Security logs xətası:",
                error
            );

            return res.status(500).json({
                error: "Logları gətirmək mümkün olmadı."
            });
        }
    }
);

app.listen(PORT, function () {
    console.log("");
    console.log("==================================");
    console.log("Sağlam Həyat Klinikası");
    console.log("==================================");
    console.log(`Sayt: http://localhost:${PORT}`);
    console.log(`Növbələr paneli: http://localhost:${PORT}/admin.html`);
    console.log(`İstifadəçilər paneli: http://localhost:${PORT}/users-admin.html`);
    console.log(`Security Logs: http://localhost:${PORT}/logs-admin.html`);
    console.log("==================================");
    console.log("");
});