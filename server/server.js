import express from 'express';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import User from './Schema/User.js';
import { nanoid } from 'nanoid';

const server = express();
server.use(express.json()); // to parse JSON request body
let PORT = 3000;

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

mongoose.connect(process.env.MONGO_URL, {
    autoIndex: true
});

const formatDatatoSend = (user) => {
    return {
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    };
}

const generateUsername = async (email) => {
    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.exists({ "personal_info.username": username });
    if (isUsernameNotUnique) {
        username += nanoid().substring(0, 4);
    }
    return username;
}

server.post("/signup", async (req, res) => {
    let { fullname, email, password } = req.body;

    // Fullname validation
    if (fullname.length < 3) {
        return res.status(403).json({ "error": "Fullname must be at least 3 letters long" });
    }

    // Email validation
    if (!email.length) {
        return res.status(403).json({ "error": "Enter Email" });
    }

    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email is invalid" });
    }

    // Password validation
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Invalid password" });
    }

    // Hash password and save user
    try {
        const hashed_password = await bcrypt.hash(password, 10);
        const username = await generateUsername(email);

        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username }
        });

        let savedUser = await user.save();
        return res.status(200).json(formatDatatoSend(savedUser));
    } catch (err) {
        if (err.code == 11000) {
            return res.status(500).json({ "error": "Email already exists" });
        }
        return res.status(500).json({ "error": err.message });
    }
});

server.listen(PORT, () => {
    console.log('Listening on port -> ' + PORT);
});
