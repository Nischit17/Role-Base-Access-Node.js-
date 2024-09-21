const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const register = async (req, res) => {
  try {
    const { username, password, role } = req.body;

    // Hashed password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ username, password: hashedPassword, role });

    // Save the new user to the database
    await newUser.save();
    res.status(201).json({
      message: `User registered with username ${username}`,
    });
  } catch (error) {
    console.log(error);
  }
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({
        message: `User with ${username} not found`,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        message: `Invalid credentials`,
      });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SCERET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      token,
    });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  register,
  login,
};
