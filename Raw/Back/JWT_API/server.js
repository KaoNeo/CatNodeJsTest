const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key"; // 用於加密 JWT 的密鑰

app.use(bodyParser.json());

// 模擬的使用者資料庫
const users = [];

// 註冊路由
app.post("/register", async (req, res) => {
    console.warn("===== Enter Router /register =====");
    const { username, password } = req.body;

    console.warn(`username=${username}\n password=${password}`);

    // 檢查使用者是否已存在
    const userExists = users.find((user) => user.username === username);
    if (userExists) {
        return res.status(400).json({ message: "User already exists" });
    }

    // 加密密碼並儲存
    console.warn("Start Hash Password");
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });


    users.forEach((item, index) => {
        console.warn(`[${index}]username:${item.username}`);
        console.warn(`[${index}]password:${item.password}`);
    });

    res.json({ message: "User registered successfully" });
});

// 登入路由
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    // 檢查使用者是否存在
    const user = users.find((user) => user.username === username);
    if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
    }

    // 驗證密碼
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid credentials" });
    }

    // 生成 JWT
    const token = jwt.sign({ username: user.username }, SECRET_KEY, {
        expiresIn: "1h",
    });
    res.json({ token });
});

// 驗證中介層
const authenticateJWT = (req, res, next) => {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Token is not valid" });
        }
        req.user = user;
        next();
    });
};

// 受保護的路由
app.get("/protected", authenticateJWT, (req, res) => {
    res.json({ message: `Hello, ${req.user.username}! You have access to this protected route.` });
});


// GET

app.get("/mycat", (req, res) => {
    console.log("/mycat ");
    res.send({
        status: 200,
        message: "獲取使用者資料成功"
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
