const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const EmployeeModel = require("./model/Employee");
const morgan = require("morgan");
require("dotenv").config();
const bcrypt = require("bcrypt");
const saltRounds = 10;
const helmet = require("helmet");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("tiny"));
app.use(helmet());

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => {
    console.log("MongoDB is Connected Successfully");
  })
  .catch((error) => {
    console.log(error);
    
    
  });

// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await EmployeeModel.findOne({ email });
    if (!user) {
      return res.status(404).json({
        message: "User not found",
        status: 404,
        data: null,
        error: true,
      });
    }

    const passMatch = await bcrypt.compare(password, user.password);
    if (!passMatch) {
      return res.status(403).json({
        message: "Password invalid",
        status: 403,
        data: null,
        error: true,
      });
    }

    jwt.sign(
      { name: user.name, email: user.email },
      process.env.PRIVATEKEY,
      (err, token) => {
        if (err) {
          return res.status(500).json({
            message: "Token generation failed",
            error: true,
          });
        }

        res.status(200).json({
          message: "Login successful",
          status: 200,
          user,
          token,
          error: false,
        });
      }
    );
  } catch (err) {
    console.log(`Login Error: ${err}`);
    res.status(500).json({
      message: "Internal server error",
      error: true,
    });
  }
});

// Password Hash Middleware
async function passHash(req, res, next) {
  const { password } = req.body;
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hashPass = await bcrypt.hash(password, salt);
    req.body.password = hashPass;
    next();
  } catch (err) {
    console.log(`Password hashing failed: ${err}`);
    res.status(500).json({
      message: "Password hashing error",
      error: true,
    });
  }
}

// Register Route
app.post("/register", passHash, (req, res) => {
  EmployeeModel.create(req.body)
    .then((employees) => res.status(201).json(employees))
    .catch((err) => res.status(500).json({ error: err.message }));
});

// Server Start
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server is Running on port ${PORT}`);
});
