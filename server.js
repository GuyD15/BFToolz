require('dotenv').config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// PostgreSQL Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for secure connections on cloud-hosted Postgres
});

pool.connect(err => {
    if (err) {
        console.error('Error connecting to PostgreSQL:', err);
        return;
    }
    console.log('Connected to PostgreSQL database.');
});

// Middleware to authenticate admin token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];
    
    if (!token) return res.sendStatus(401); // Unauthorized if token is missing

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); // Forbidden if token is invalid
        req.user = user;
        next();
    });
}

// Admin login endpoint
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query("SELECT * FROM admins WHERE username = $1", [username]);
        const admin = result.rows[0];

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ username: admin.username }, process.env.SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ message: "Database error" });
    }
});

// Fetch pages and subpages
app.get("/pages", async (req, res) => {
    try {
        const mainPagesResult = await pool.query("SELECT * FROM pages WHERE parent_id IS NULL");
        const mainPages = mainPagesResult.rows;

        const pagesWithSubpages = await Promise.all(mainPages.map(async (page) => {
            const subpagesResult = await pool.query("SELECT * FROM pages WHERE parent_id = $1", [page.id]);
            page.subpages = subpagesResult.rows;
            return page;
        }));

        res.json(pagesWithSubpages);
    } catch (error) {
        console.error("Error fetching pages:", error);
        res.status(500).json({ message: "Database error" });
    }
});

// Add a new page or subpage (admin-only)
app.post("/pages", authenticateToken, async (req, res) => {
    const { title, content, parent_id = null } = req.body;

    try {
        const result = await pool.query(
            "INSERT INTO pages (title, content, parent_id) VALUES ($1, $2, $3) RETURNING *",
            [title, content, parent_id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        console.error("Error inserting page:", error);
        res.status(500).json({ message: "Database error" });
    }
});

// Update a page (admin-only)
app.put("/pages/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, content } = req.body;

    try {
        await pool.query(
            "UPDATE pages SET title = $1, content = $2 WHERE id = $3",
            [title, content, id]
        );
        res.json({ message: "Page updated successfully" });
    } catch (error) {
        console.error("Error updating page:", error);
        res.status(500).json({ message: "Database update error" });
    }
});

// Delete a page (admin-only)
app.delete("/pages/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.query("DELETE FROM pages WHERE id = $1", [id]);
        res.json({ message: "Page deleted successfully" });
    } catch (error) {
        console.error("Error deleting page:", error);
        res.status(500).json({ message: "Database deletion error" });
    }
});

// Serve static files for the frontend
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start the server on the specified port or default to 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
