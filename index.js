require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const app = express();
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");


const port = process.env.PORT || 5000;
app.use(cookieParser());
app.use(express.json());
app.use(cors({
     origin: "http://localhost:5173", // frontend URL
    credentials: true
}));

mongoose.connect(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASS}@cluster-1.atolsgl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster-1`)
.then(() => console.log("MongoDB connected!"))
.catch(err => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
    name: String,
    email: {type: String, unique: true},
    password: String
});

const User = mongoose.model("User", userSchema);

app.post("/register", async ( req, res ) => {
    try{
        const {name, email, password} = req.body;
        const existingUser = await User.findOne({email});
        if(existingUser) {
            return res.status(400).json({message: 'This user already registered'})
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({name, email, password: hashedPassword})
        await user.save();

        res.status(200).json({message: "User registered successfully"})
    }
    catch(err) {
        res.status(500).json({ error: err.message });
    }
})

app.post("/login", async ( req, res ) => {
    try{
        const {email, password} = req.body;
        const user = await User.findOne({email});

        if(!user) {
            return res.status(400).json({message: "Invalid email or password"});
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) {
            return res.status(400).json({message: "Invalid email or password"})
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {
            expiresIn: "1d"
        });

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000,
        });

        res.status(200).json({message: "Login successful"})
    }
    catch(err) {
        res.status(500).json({error: err.message})
    }
});

app.get("/profile", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Not Authenticated" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    res.json({ message: "Welcome to your profile", user });
  } catch (err) {
    res.status(403).json({ message: "Invalid token" });
  }
});


app.listen(5000, () => console.log("Server running on http://localhost:5000"));