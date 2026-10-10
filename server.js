const crypto = require("crypto");
const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Database
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "appointments.db");
const db = new sqlite3.Database(DB_PATH);

function initializeDatabase(callback) {
    db.run(`
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT NOT NULL,
            service TEXT NOT NULL,
            contact TEXT NOT NULL,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `, (createErr) => {
        if (createErr) return callback(createErr);

        db.all("PRAGMA table_info(appointments)", (pragmaErr, rows) => {
            if (pragmaErr) return callback(pragmaErr);

            const existing = new Set(rows.map(row => row.name));
            const migrations = [
                ["email", "TEXT"],
                ["address", "TEXT"],
                ["preferredDate", "TEXT"],
                ["preferredTime", "TEXT"],
                ["message", "TEXT"],
                ["paymentMethod", "TEXT"],
                ["paymentTiming", "TEXT"],
                ["status", "TEXT DEFAULT 'Pending'"],
                ["requestKey", "TEXT"],
                ["requestHash", "TEXT"]
            ];

            function addNext(index) {
                if (index >= migrations.length) {
                    return db.run(
                        `CREATE UNIQUE INDEX IF NOT EXISTS
                         idx_appointments_requestKey
                         ON appointments(requestKey)`,
                        callback
                    );
                }

                const [name, definition] = migrations[index];

                if (existing.has(name)) {
                    return addNext(index + 1);
                }

                db.run(
                    `ALTER TABLE appointments ADD COLUMN ${name} ${definition}`,
                    (alterErr) => {
                        if (alterErr) return callback(alterErr);
                        addNext(index + 1);
                    }
                );
            }

            addNext(0);
        });
    });
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Website files
app.use(express.static(path.join(__dirname, "public")));

// Admin login and session protection
const adminSessions = new Map();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_LIFETIME = 8 * 60 * 60 * 1000;

function requireAdmin(req, res, next) {
    const cookies = req.headers.cookie || "";
    const match = cookies.match(/(?:^|;\s*)lma_admin=([a-f0-9]+)/);
    const token = match ? match[1] : "";
    const session = adminSessions.get(token);

    if (!session || session.expiresAt <= Date.now()) {
        if (token) adminSessions.delete(token);
        return res.status(401).json({
            success: false,
            message: "Admin login required."
        });
    }

    next();
}

app.post("/api/admin/login", (req, res) => {
    if (!ADMIN_PASSWORD) {
        return res.status(503).json({
            success: false,
            message: "Admin password is not configured on the server."
        });
    }

    const submitted = Buffer.from(String(req.body.password || ""));
    const expected = Buffer.from(ADMIN_PASSWORD);

    if (
        submitted.length !== expected.length ||
        !crypto.timingSafeEqual(submitted, expected)
    ) {
        return res.status(401).json({
            success: false,
            message: "Incorrect password."
        });
    }

    const token = crypto.randomBytes(32).toString("hex");
    adminSessions.set(token, {
        expiresAt: Date.now() + SESSION_LIFETIME
    });

    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader(
        "Set-Cookie",
        "lma_admin=" + token +
        "; HttpOnly; SameSite=Strict; Path=/api; Max-Age=28800" + secure
    );

    res.json({ success: true, message: "Admin login successful." });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
    const cookies = req.headers.cookie || "";
    const match = cookies.match(/(?:^|;\s*)lma_admin=([a-f0-9]+)/);

    if (match) adminSessions.delete(match[1]);

    res.setHeader(
        "Set-Cookie",
        "lma_admin=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0" +
        (process.env.NODE_ENV === "production" ? "; Secure" : "")
    );

    res.json({ success: true, message: "Logged out." });
});


// CREATE - Submit application
app.post("/api/appointments", (req, res) => {
    const {
            fullName, service, contact, email, address,
            preferredDate, preferredTime, message, paymentMethod
        } = req.body;

    if (!fullName || !service || !contact || !paymentMethod) {
        return res.status(400).json({
            success: false,
            message: "Please complete the required fields."
        });
    }

    if (!["GCash", "Maya", "Bank Transfer", "Cash", "Other"].includes(paymentMethod)) {
            return res.status(400).json({
                success: false,
                message: "Please select a valid payment method."
            });
        }

        const requestKey = String(
        req.body.requestKey || crypto.randomUUID()
    ).trim();

    if (requestKey.length > 128) {
        return res.status(400).json({
            success: false,
            message: "Invalid request key."
        });
    }

    const payload = {
        fullName, service, contact,
        email: email || "",
        address: address || "",
        preferredDate: preferredDate || "",
        preferredTime: preferredTime || "",
        message: message || "",
            paymentMethod,
            paymentTiming: "After Approval"
    };

    const requestHash = crypto
        .createHash("sha256")
        .update(JSON.stringify(payload))
        .digest("hex");

    const sql = `
        INSERT INTO appointments (
                fullName, service, contact, email, address,
                preferredDate, preferredTime, message,
                paymentMethod, paymentTiming, status,
                requestKey, requestHash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
    `;

    db.run(sql, [
        payload.fullName, payload.service, payload.contact,
        payload.email, payload.address, payload.preferredDate,
        payload.preferredTime, payload.message, payload.paymentMethod, payload.paymentTiming,
            requestKey, requestHash
    ], function (err) {
        if (!err) {
            return res.json({
                success: true,
                message: "Application submitted successfully!",
                id: this.lastID
            });
        }

        if (err.message.includes("UNIQUE constraint failed")) {
            return db.get(
                "SELECT id, requestHash FROM appointments WHERE requestKey = ?",
                [requestKey],
                (lookupErr, existing) => {
                    if (lookupErr) {
                        return res.status(500).json({
                            success: false,
                            message: "Could not verify previous submission."
                        });
                    }

                    if (!existing) {
                        return res.status(500).json({
                            success: false,
                            message: "Failed to save application."
                        });
                    }

                    if (existing.requestHash !== requestHash) {
                        return res.status(409).json({
                            success: false,
                            message: "Request key already used for another application."
                        });
                    }

                    return res.json({
                        success: true,
                        duplicate: true,
                        message: "This application was already received.",
                        id: existing.id
                    });
                }
            );
        }

        console.error("Appointment save error:", err.message);
        return res.status(500).json({
            success: false,
            message: "Failed to save application."
        });
    });
});

// READ - View applications
app.get("/api/appointments", requireAdmin, (req, res) => {
    db.all(
        "SELECT * FROM appointments ORDER BY id DESC",
        [],
        (err, rows) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Failed to load applications."
                });
            }

            res.json(rows);
        }
    );
});

// UPDATE - Update appointment
app.put("/api/appointments/:id", requireAdmin, (req, res) => {
    const { id } = req.params;

    const allowedFields = [
        "fullName",
        "service",
        "contact",
        "email",
        "address",
        "preferredDate",
        "preferredTime",
        "message",
        "status"
    ];

    const updates = [];
    const values = [];

    for (const field of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
            updates.push(`${field} = ?`);
            values.push(req.body[field] ?? "");
        }
    }

    if (updates.length === 0) {
        return res.status(400).json({
            success: false,
            message: "No fields to update."
        });
    }

    values.push(id);

    const sql = `
        UPDATE appointments
        SET ${updates.join(", ")}
        WHERE id = ?
    `;

    db.run(sql, values, function (err) {
        if (err) {
            console.error(err);

            return res.status(500).json({
                success: false,
                message: "Failed to update appointment."
            });
        }

        if (this.changes === 0) {
            return res.status(404).json({
                success: false,
                message: "Appointment not found."
            });
        }

        res.json({
            success: true,
            message: "Appointment updated successfully."
        });
    });
});
// DELETE - Delete appointment
app.delete("/api/appointments/:id", requireAdmin, (req, res) => {
    const { id } = req.params;

    db.run(
        "DELETE FROM appointments WHERE id = ?",
        [id],
        function (err) {
            if (err) {
                console.error(err);

                return res.status(500).json({
                    success: false,
                    message: "Failed to delete appointment."
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Appointment not found."
                });
            }

            res.json({
                success: true,
                message: "Appointment deleted successfully."
            });
        }
    );
});

// Start server only after database migrations finish
initializeDatabase((err) => {
    if (err) {
        console.error("Database initialization failed:", err.message);
        process.exit(1);
    }

    app.listen(PORT, () => {
        console.log(
            `Leah Mae Online Assistance running at http://localhost:${PORT}`
        );
    });
});
