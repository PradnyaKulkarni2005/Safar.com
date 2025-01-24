// Importing required modules
const express = require('express'); // Framework for building web applications
const path = require('path'); // Module to handle file and directory paths
const bodyParser = require('body-parser'); // Middleware to parse incoming request bodies
const session = require('express-session'); // Middleware to manage user sessions
const bcrypt = require('bcryptjs'); // Library for hashing passwords securely
const jwt = require('jsonwebtoken'); // Library for generating and verifying JSON Web Tokens (JWT)
const mysql = require('mysql'); // MySQL module to interact with the database
require('dotenv').config(); // Module to load environment variables from a .env file

// Initializing the Express application
const app = express();
const PORT = process.env.PORT || 4000; // Setting the port for the server, default to 4000 if not in .env

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true })); // Parses URL-encoded bodies (form submissions)
app.use(express.static(path.join(__dirname, '../Frontend'))); // Serves static files (e.g., HTML, CSS, JS) from the 'Frontend' directory

// Session setup (for basic server-side session handling)
app.use(session({
  secret: 'secret', // Secret key used to sign the session ID cookie
  resave: true, // Forces session to be saved even if it wasn't modified during the request
  saveUninitialized: true // Saves new sessions that haven't been modified yet
}));

// MySQL database connection setup
const db = mysql.createConnection({
  host: process.env.DB_HOST, // Database host (e.g., localhost or a cloud database host)
  user: process.env.DB_USER, // Database username
  password: process.env.DB_PASSWORD, // Database password
  database: process.env.DB_NAME, // Name of the database
  connectTimeout: 10000 // Sets the connection timeout to 10 seconds
});

// Function to handle database connection retries
function connectWithRetry() {
  db.connect(err => {
    if (err) {
      console.error("Database connection failed. Retrying in 5 seconds...", err.message);
      setTimeout(connectWithRetry, 5000); // Retry after 5 seconds if connection fails
    } else {
      console.log("Connected to the database successfully");
    }
  });
}
connectWithRetry(); // Initiates the connection retry mechanism

// Routes
// Root route - Serves the main index page
app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../Frontend/index.html')); // Sends the 'index.html' file
});

// Route to serve the login page
app.get('/login', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../Frontend/login.html')); // Sends the 'login.html' file
});

// Route to serve the signup page
app.get('/signup', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../Frontend/signup.html')); // Sends the 'signup.html' file
});

// Signup route - Handles user registration
app.post('/signup', (req, res) => {
  const { email, password } = req.body; // Extracts email and password from the request body
  const hashedPassword = bcrypt.hashSync(password, 10); // Hashes the password with a salt factor of 10
  const query = 'INSERT INTO users(email, password) VALUES(?, ?)'; // SQL query to insert user details
  db.query(query, [email, hashedPassword], err => {
    if (err) return res.status(500).send("Error registering user"); // Handles database errors
    res.send('User Registered Successfully!'); // Sends success message
  });
});

// Login route - Handles user authentication
const JWT_SECRET = process.env.JWT_SECRET; // Secret key for signing JWTs
app.post('/login', (req, res) => {
  const { email, password } = req.body; // Extracts email and password from the request body
  const query = 'SELECT * FROM users WHERE email = ?'; // SQL query to fetch user by email
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).send("Error logging in"); // Handles database errors
    if (results.length > 0) { // If user exists
      const user = results[0]; // Gets the user record
      if (bcrypt.compareSync(password, user.password)) { // Compares hashed password
        // Generates a JWT if the password matches
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour
        res.json({ message: 'Login Successful!', token }); // Sends success message and token
      } else {
        res.status(401).send('Invalid Password'); // Sends error if password is incorrect
      }
    } else {
      res.status(404).send('User not found'); // Sends error if user does not exist
    }
  });
});

// Middleware for JWT authentication
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extracts the token from the Authorization header
  if (!token) return res.status(403).send('Access denied. No token provided'); // Sends error if token is missing
  try {
    const decoded = jwt.verify(token, JWT_SECRET); // Verifies and decodes the token
    req.user = decoded; // Attaches decoded data to the request object
    next(); // Passes control to the next middleware or route handler
  } catch (err) {
    res.status(401).send('Invalid token'); // Sends error if token verification fails
  }
};

// Starting the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`); // Logs the server startup message
});
