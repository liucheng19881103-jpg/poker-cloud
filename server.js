const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // 让电脑把当前文件夹变成网站
// ================================================================
// ⚠️ 请填入你的 MongoDB 连接字符串
// 建议去 MongoDB Atlas 修改密码，这里不要用之前泄露的密码
const MONGO_URI = 'mongodb+srv://liucheng19881103_db_user:ueA7DDuDQCOiGugo@pokersave.sz7bsqp.mongodb.net/?appName=pokersave';
// ================================================================

const JWT_SECRET = 'PokerCloud_Secret_Key_2024'; // 用于加密 Token 的密钥

// 连接数据库
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected!'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- 模型定义 ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

const HandSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // 关联 User ID
    ownerName: String, // 冗余存一个用户名，方便显示
    timestamp: Number,
    dateStr: String,
    game: Object,
    hero: Object,
    villains: Array,
    board: Array,
    logs: Array
});
const Hand = mongoose.model('Hand', HandSchema);

// --- 中间件: 验证 Token ---
const auth = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access Denied' });

    try {
        // 去掉 "Bearer " 前缀
        const verified = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
        req.user = verified; // 把解密出的用户信息存入 req.user
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid Token' });
    }
};

// --- API 接口 ---

// 1. 注册
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // 检查用户名是否已存在
        const exist = await User.findOne({ username });
        if (exist) return res.status(400).json({ error: 'Username already taken' });

        // 密码加密
        const salt = await bcrypt.genSalt(10);
        const hashPass = await bcrypt.hash(password, salt);

        // 创建用户
        const user = new User({ username, password: hashPass });
        await user.save();
        res.json({ message: 'Register Success! Please Login.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. 登录
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        // 找用户
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found' });

        // 验密码
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Wrong password' });

        // 发 Token (有效期 30 天)
        const token = jwt.sign({ _id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ token, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. 保存牌谱 (需要登录)
app.post('/api/hands', auth, async (req, res) => {
    try {
        // 创建数据时，自动加上 owner 信息
        const handData = {
            ...req.body,
            owner: req.user._id,
            ownerName: req.user.username
        };
        const hand = new Hand(handData);
        await hand.save();
        console.log(`[Saved] Hand for ${req.user.username}`);
        res.status(201).json(hand);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. 获取“我的”历史牌谱 (需要登录)
app.get('/api/hands/my', auth, async (req, res) => {
    try {
        // 只查找当前登录用户的数据
        const hands = await Hand.find({ owner: req.user._id }).sort({ timestamp: -1 });
        res.json(hands);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. 删除牌谱 (需要登录)
app.delete('/api/hands/:id', auth, async (req, res) => {
    try {
        // 确保只能删除自己的
        const result = await Hand.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
        if (!result) return res.status(404).json({ error: 'Hand not found or not owned by you' });
        res.json({ message: 'Deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on Port ${PORT}`));