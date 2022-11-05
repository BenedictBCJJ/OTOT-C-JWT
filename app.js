require("dotenv").config();
require("./config/database").connect("");
const express = require("express");

const app = express();

app.use(express.json());

// importing user context
const User = require("./model/user");

// Register
app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;
    if (!(email && password)) {
      res
        .status(400)
        .send("Please enter both email and password for registration");
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
    });

    const token = jwt.sign(
      { user_id: user._id, email },
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
app.post("/login", (req, res) => {
  // our login logic goes here
});

module.exports = app;
