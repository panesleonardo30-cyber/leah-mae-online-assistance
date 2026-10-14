const express = require("express");
const crypto = require("crypto");

module.exports = function createNewsfeedRoutes(pool, config = {}) {
    const router = express.Router();
    const requireAdmin = config.requireAdmin;

    async function requireCustomer(req, res, next) {
        try {
            const cookies = req.headers.cookie || "";
            const match = cookies.match(
                /(?:^|;\s*)lma_customer=([a-f0-9]{64})/
            );

            if (!match) {
                return res.status(401).json({
                    success: false,
                    message: "Mag-login muna sa iyong customer account."
                });
            }

            const tokenHash = crypto
                .createHash("sha256")
                .update(match[1])
                .digest("hex");

            const result = await pool.query(`
                SELECT a.id, a.full_name
                FROM public.customer_sessions s
                JOIN public.customer_accounts a
                    ON a.id = s.customer_id
                WHERE s.token_hash = $1
                  AND s.expires_at > NOW()
            `, [tokenHash]);

            if (!result.rowCount) {
                return res.status(401).json({
                    success: false,
                    message: "Mag-login muna sa iyong customer account."
                });
            }

            req.customer = result.rows[0];
            next();
        } catch (err) {
            console.error("Newsfeed customer authentication error:", err.message);
            res.status(500).json({
                success: false,
                message: "Hindi ma-verify ang customer account."
            });
        }
    }

    async function initializeNewsfeedTables() {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS public.customer_newsfeed_posts (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                customer_id BIGINT REFERENCES public.customer_accounts(id)
                    ON DELETE SET NULL,
                author_role VARCHAR(20) NOT NULL
                    CHECK (author_role IN ('customer', 'admin')),
                author_display_name VARCHAR(100) NOT NULL,
                content VARCHAR(2000) NOT NULL,
                is_published BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_customer_newsfeed_posts_created
            ON public.customer_newsfeed_posts
                (is_published, created_at DESC, id DESC)
        `);
    }

    // Published posts only. Customer must be logged in.
    router.get("/api/customer/newsfeed", requireCustomer, async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT
                    id,
                    author_role AS "authorRole",
                    author_display_name AS "authorName",
                    content,
                    created_at AS "createdAt",
                    (customer_id = $1) AS "isOwnPost"
                FROM public.customer_newsfeed_posts
                WHERE is_published = TRUE
                ORDER BY created_at DESC, id DESC
                LIMIT 100
            `, [req.customer.id]);

            res.json({
                success: true,
                posts: result.rows
            });
        } catch (err) {
            console.error("Newsfeed load error:", err.message);
            res.status(500).json({
                success: false,
                message: "Hindi ma-load ang Newsfeed sa ngayon."
            });
        }
    });

    // Customers can publish plain-text posts under their own identity.
    router.post("/api/customer/newsfeed", requireCustomer, async (req, res) => {
        try {
            const content = typeof req.body.content === "string"
                ? req.body.content.trim()
                : "";

            if (!content || content.length > 2000) {
                return res.status(400).json({
                    success: false,
                    message: "Ang post ay dapat may laman at hindi lalampas sa 2,000 character."
                });
            }

            const displayName = String(req.customer.full_name || "Customer")
                .trim()
                .slice(0, 100) || "Customer";

            const result = await pool.query(`
                INSERT INTO public.customer_newsfeed_posts
                    (customer_id, author_role, author_display_name, content)
                VALUES ($1, 'customer', $2, $3)
                RETURNING
                    id,
                    author_role AS "authorRole",
                    author_display_name AS "authorName",
                    content,
                    created_at AS "createdAt",
                    TRUE AS "isOwnPost"
            `, [req.customer.id, displayName, content]);

            res.status(201).json({
                success: true,
                message: "Na-publish ang iyong post.",
                post: result.rows[0]
            });
        } catch (err) {
            console.error("Newsfeed customer post error:", err.message);
            res.status(500).json({
                success: false,
                message: "Hindi na-publish ang post sa ngayon."
            });
        }
    });

    // Only the owner can delete their own customer post.
    router.delete(
        "/api/customer/newsfeed/:id",
        requireCustomer,
        async (req, res) => {
            try {
                if (!/^\d+$/.test(req.params.id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Hindi valid ang post ID."
                    });
                }

                const result = await pool.query(`
                    DELETE FROM public.customer_newsfeed_posts
                    WHERE id = $1
                      AND customer_id = $2
                      AND author_role = 'customer'
                    RETURNING id
                `, [req.params.id, req.customer.id]);

                if (!result.rowCount) {
                    return res.status(404).json({
                        success: false,
                        message: "Hindi makita ang post o hindi ikaw ang may-ari nito."
                    });
                }

                res.json({
                    success: true,
                    message: "Na-delete ang iyong post."
                });
            } catch (err) {
                console.error("Newsfeed post delete error:", err.message);
                res.status(500).json({
                    success: false,
                    message: "Hindi ma-delete ang post sa ngayon."
                });
            }
        }
    );


    // Admin-only newsfeed listing.
    if (typeof requireAdmin === "function") {
        router.get("/api/admin/newsfeed", requireAdmin, async (req, res) => {
            try {
                const result = await pool.query(`
                    SELECT id,
                           author_role AS "authorRole",
                           author_display_name AS "authorName",
                           content,
                           created_at AS "createdAt"
                    FROM public.customer_newsfeed_posts
                    ORDER BY created_at DESC, id DESC
                    LIMIT 200
                `);
                res.json({ success: true, posts: result.rows });
            } catch (err) {
                console.error("Admin newsfeed list error:", err.message);
                res.status(500).json({
                    success: false,
                    message: "Hindi ma-load ang admin newsfeed."
                });
            }
        });
    }

    // Only an authenticated admin can publish official advertisements.
    if (typeof requireAdmin === "function") {
        router.post(
            "/api/admin/newsfeed",
            requireAdmin,
            async (req, res) => {
                try {
                    const content = typeof req.body.content === "string"
                        ? req.body.content.trim()
                        : "";

                    if (!content || content.length > 2000) {
                        return res.status(400).json({
                            success: false,
                            message: "Ang anunsiyo ay dapat may laman at hindi lalampas sa 2,000 character."
                        });
                    }

                    const result = await pool.query(`
                        INSERT INTO public.customer_newsfeed_posts
                            (customer_id, author_role, author_display_name, content)
                        VALUES (NULL, 'admin', 'Leah Mae Official', $1)
                        RETURNING
                            id,
                            author_role AS "authorRole",
                            author_display_name AS "authorName",
                            content,
                            created_at AS "createdAt"
                    `, [content]);

                    res.status(201).json({
                        success: true,
                        message: "Na-publish ang official announcement.",
                        post: result.rows[0]
                    });
                } catch (err) {
                    console.error("Official newsfeed post error:", err.message);
                    res.status(500).json({
                        success: false,
                        message: "Hindi ma-publish ang official announcement."
                    });
                }
            }
        );

        // Admin-only post moderation.
        router.delete(
            "/api/admin/newsfeed/:id",
            requireAdmin,
            async (req, res) => {
                try {
                    if (!/^\d+$/.test(req.params.id)) {
                        return res.status(400).json({
                            success: false,
                            message: "Hindi valid ang post ID."
                        });
                    }

                    const result = await pool.query(`
                        DELETE FROM public.customer_newsfeed_posts
                        WHERE id = $1
                        RETURNING id
                    `, [req.params.id]);

                    if (!result.rowCount) {
                        return res.status(404).json({
                            success: false,
                            message: "Hindi makita ang post."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Na-delete ang post."
                    });
                } catch (err) {
                    console.error("Admin newsfeed moderation error:", err.message);
                    res.status(500).json({
                        success: false,
                        message: "Hindi ma-delete ang post sa ngayon."
                    });
                }
            }
        );
    }

    return {
        router,
        initializeNewsfeedTables
    };
};
