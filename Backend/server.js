const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// JWT Secret - Move to .env in production!
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json()); // bodyParser.json() is redundant with this

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "Finance and user dashboard",
  password: "Quantum_190703",
  port: 5432,
});

// Test DB connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("Connection error:", err.stack);
  } else {
    console.log("Database connected:", res.rows[0]);
  }
});

const authenticateToken = (req, res, next) => {
  // Extract token from Authorization header (format: "Bearer <token>")
  const token = req.header("Authorization")?.split(" ")[1];

  // Check if token is missing
  if (!token) {
    return res
      .status(401)
      .json({ message: "Access Denied: No token provided" });
  }

  try {
    // Verify token using JWT_SECRET (matches your earlier code)
    const decoded = jwt.verify(token, "your_secret_key"); // Move to .env in production!
    req.user = decoded; // Attach decoded payload (includes userId) to req
    next(); // Proceed to the route handler
  } catch (err) {
    // Handle invalid or expired tokens
    console.error("Token verification error:", err.message);
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

// Register Route
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || email.trim() === "" || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Check if user exists
    const existingUserQuery = "SELECT * FROM users WHERE email = $1";
    const existingUser = await pool.query(existingUserQuery, [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const insertQuery =
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email";
    const result = await pool.query(insertQuery, [
      email.trim(),
      hashedPassword,
    ]);

    res.status(201).json({
      id: result.rows[0].id,
      message: "User registered successfully",
      user: { email: result.rows[0].email },
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Signin Route
app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Fetch user
    const userQuery = "SELECT id, email, password FROM users WHERE email = $1";
    const result = await pool.query(userQuery, [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }

    const user = result.rows[0];

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Generate JWT
    const payload = { userId: user.id, email: user.email };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({
      message: "Login successful",
      token,
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Transaction route
app.post("/transactions", authenticateToken, async (req, res) => {
  try {
    // Extract input from request body
    const { amount, type, date, category, description } = req.body;

    // Validate amount: must exist and be positive
    if (!amount || typeof amount !== "number" || amount <= 0) {
      return res
        .status(400)
        .json({ error: "Amount must be a positive number" });
    }

    // Validate type: must be "income" or "expense"
    if (!["income", "expense"].includes(type)) {
      return res
        .status(400)
        .json({ error: "Type must be 'income' or 'expense'" });
    }

    // Validate date: must be in YYYY-MM-DD format
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(Date.parse(date))) {
      return res
        .status(400)
        .json({ error: "Date must be in YYYY-MM-DD format" });
    }

    // Validate category: must exist and not be empty
    if (!category || category.trim() === "") {
      return res.status(400).json({ error: "Category is required" });
    }

    // Description is optional, default to null if not provided
    const finalDescription = description ? description.trim() : null;

    // Insert transaction into database
    const insertQuery = `
      INSERT INTO transactions (user_id, amount, type, date, category, description)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `;

    const result = await pool.query(insertQuery, [
      req.user.userId, // From JWT token (authenticateToken sets this)
      amount,
      type,
      date,
      category,
      finalDescription,
    ]);

    // Return the newly created transaction
    res.status(201).json(result.rows[0]);
  } catch (err) {
    // Log error for debugging and return generic server error
    console.error("Database error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/transactions", authenticateToken, async (req, res) => {
  try {
    // 1. Get the user_id from the JWT token
    const userId = req.user.userId; // Extract userId from JWT payload

    // 2. Query the database for transactions
    const userQuery = "SELECT * FROM transactions WHERE user_id = $1";
    const result = await pool.query(userQuery, [userId]); // Execute query and store result

    // 3. Handle the result
    if (result.rows.length === 0) {
      return res.status(200).json([]); // Empty array is fine for "no data"
    }

    // 4. Send the response
    res.status(200).json(result.rows);
  } catch (err) {
    // 5. Error handling
    console.error("Database error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/transactions/:id", authenticateToken, async (req, res) => {
  try {
    // 1. Get the user_id from the JWT token
    const userId = req.user.userId;

    // 2. Get and validate the transaction ID from the URL parameter
    const transactionId = parseInt(req.params.id, 10); // Convert string to integer
    if (isNaN(transactionId) || transactionId <= 0) {
      return res.status(400).json({ error: "Invalid transaction ID" });
    }

    // 3. Query the database to delete the transaction
    const deleteQuery =
      "DELETE FROM transactions WHERE id = $1 AND user_id = $2 RETURNING *";
    const result = await pool.query(deleteQuery, [transactionId, userId]);

    // 4. Check the result
    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ error: "Transaction not found or not owned by user" });
    }

    // 5. Send the response
    res.status(200).json({
      message: "Transaction deleted",
      deletedTransaction: result.rows[0], // Optional: return the deleted row
    });
  } catch (err) {
    // 6. Error handling
    console.error("Database error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
