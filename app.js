require("dotenv").config();
require("./config/database").connect("");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Role = require("./role/role.js");
const app = express();

app.use(express.json());

// importing user context
const User = require("./model/user");
const auth = require("./middleware/auth");
const authAdmin = require("./middleware/authadmin");

app.post("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome you are either a user or a admin. 🙌 ");
});

app.post("/adminpage", authAdmin, (req, res) => {
  res.status(200).send("You are an administrator welcome. 🙌 ");
});
// Register
app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { email, password, role } = req.body;
    if (!(email && password && role)) {
      res
        .status(400)
        .send("Please enter both email, password and role for registration");
    }

    if (!Object.keys(Role).includes(role)) {
      res.status(400).send("Please enter a valid role, Admin or User.");
    }
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(409)
        .send("This email is already in use, please login instead.");
    }

    encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
      role: role,
    });

    const token = jwt.sign(
      { user_id: user._id, email, role: role },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    const user = await User.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email, role: user.role },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );
      user.token = token;

      // user
      res.status(200).json(user);
    } else {
      res.status(400).send("Invalid Credentials");
    }
  } catch (err) {
    console.log(err);
  }
});

module.exports = app;
