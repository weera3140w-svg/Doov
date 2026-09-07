require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Database ────────────────────────────────────────────────────────────────
const db = new Database('./doov.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL,
    avatar TEXT DEFAULT NULL,
    banner TEXT DEFAULT NULL,
    bio TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    filename TEXT NOT NULL,
    thumbnail TEXT DEFAULT NULL,
    duration INTEGER DEFAULT 0,
    rating TEXT DEFAULT 'all',
    visibility TEXT DEFAULT 'public',
    views INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS likes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, video_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(video_id) REFERENCES videos(id)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(video_id) REFERENCES videos(id)
  );

  CREATE TABLE IF NOT EXISTS follows (
    id TEXT PRIMARY KEY,
    follower_id TEXT NOT NULL,
    following_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(follower_id, following_id),
    FOREIGN KEY(follower_id) REFERENCES users(id),
    FOREIGN KEY(following_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reporter_id) REFERENCES users(id),
    FOREIGN KEY(video_id) REFERENCES videos(id)
  );
`);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'doov_secret_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ─── Multer Storage ───────────────────────────────────────────────────────────
const avatarStorage = multer.diskStorage({
  destination: './public/uploads/avatars/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});

const videoStorage = multer.diskStorage({
  destination: './public/uploads/videos/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});

const thumbStorage = multer.diskStorage({
  destination: './public/uploads/thumbnails/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});

const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/image\/(jpeg|png|gif|webp)/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only image/gif files allowed'));
  }
});

const uploadVideo = multer({
  storage: videoStorage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/video\//.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only video files allowed'));
  }
});

const uploadThumb = multer({
  storage: thumbStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/image\//.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only image files allowed'));
  }
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// ─── API: Auth ────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password, display_name } = req.body;
  if (!username || !email || !password || !display_name)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    db.prepare('INSERT INTO users (id,username,email,password,display_name) VALUES (?,?,?,?,?)')
      .run(id, username.toLowerCase(), email.toLowerCase(), hash, display_name);
    req.session.userId = id;
    const user = db.prepare('SELECT id,username,email,display_name,avatar,bio FROM users WHERE id=?').get(id);
    res.json({ success: true, user });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      res.status(400).json({ error: 'Username or email already taken' });
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?')
    .get(username.toLowerCase(), username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  res.json({ success: true, user: { id: user.id, username: user.username, display_name: user.display_name, avatar: user.avatar } });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id,username,email,display_name,avatar,bio FROM users WHERE id=?').get(req.session.userId);
  res.json({ user });
});

// ─── API: Profile ─────────────────────────────────────────────────────────────
app.post('/api/profile/avatar', requireAuth, uploadAvatar.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const avatarPath = '/uploads/avatars/' + req.file.filename;
  db.prepare('UPDATE users SET avatar=? WHERE id=?').run(avatarPath, req.session.userId);
  res.json({ success: true, avatar: avatarPath });
});

app.post('/api/profile/update', requireAuth, (req, res) => {
  const { display_name, bio } = req.body;
  db.prepare('UPDATE users SET display_name=?, bio=? WHERE id=?')
    .run(display_name, bio, req.session.userId);
  res.json({ success: true });
});

app.get('/api/profile/:username', (req, res) => {
  const user = db.prepare('SELECT id,username,display_name,avatar,bio,created_at FROM users WHERE username=?')
    .get(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const videos = db.prepare(`
    SELECT v.*, u.display_name, u.avatar, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count
    FROM videos v JOIN users u ON v.user_id=u.id
    WHERE v.user_id=? AND v.visibility='public'
    ORDER BY v.created_at DESC
  `).all(user.id);

  const followerCount = db.prepare('SELECT COUNT(*) as c FROM follows WHERE following_id=?').get(user.id).c;
  const followingCount = db.prepare('SELECT COUNT(*) as c FROM follows WHERE follower_id=?').get(user.id).c;

  let isFollowing = false;
  if (req.session.userId) {
    isFollowing = !!db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?')
      .get(req.session.userId, user.id);
  }

  res.json({ user, videos, followerCount, followingCount, isFollowing });
});

// ─── API: Videos ─────────────────────────────────────────────────────────────
app.post('/api/videos/upload', requireAuth, (req, res) => {
  uploadVideo.single('video')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'No video uploaded' });

    uploadThumb.single('thumbnail')(req, res, (err2) => {
      const { title, description, rating, visibility } = req.body;
      if (!title) return res.status(400).json({ error: 'Title required' });

      const id = uuidv4();
      const thumbPath = req.file2 ? '/uploads/thumbnails/' + req.file2.filename : null;
      const videoPath = '/uploads/videos/' + req.file.filename;

      db.prepare(`INSERT INTO videos (id,user_id,title,description,filename,thumbnail,rating,visibility)
        VALUES (?,?,?,?,?,?,?,?)`)
        .run(id, req.session.userId, title, description || '', videoPath, thumbPath, rating || 'all', visibility || 'public');

      res.json({ success: true, videoId: id });
    });
  });
});

// Upload video + thumbnail in separate middleware chain
app.post('/api/videos/create', requireAuth, (req, res) => {
  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        if (file.fieldname === 'video') cb(null, './public/uploads/videos/');
        else cb(null, './public/uploads/thumbnails/');
      },
      filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
    }),
    limits: { fileSize: 500 * 1024 * 1024 }
  }).fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]);

  upload(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });

    const { title, description, rating, visibility } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    if (!req.files?.video) return res.status(400).json({ error: 'No video file' });

    const id = uuidv4();
    const videoPath = '/uploads/videos/' + req.files.video[0].filename;
    const thumbPath = req.files?.thumbnail ? '/uploads/thumbnails/' + req.files.thumbnail[0].filename : null;

    db.prepare(`INSERT INTO videos (id,user_id,title,description,filename,thumbnail,rating,visibility)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(id, req.session.userId, title, description || '', videoPath, thumbPath, rating || 'all', visibility || 'public');

    res.json({ success: true, videoId: id });
  });
});

app.get('/api/videos', (req, res) => {
  const { search, page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;
  let query = `
    SELECT v.*, u.display_name, u.avatar, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count
    FROM videos v JOIN users u ON v.user_id=u.id
    WHERE v.visibility='public' AND v.rating != '18+'
  `;
  const params = [];
  if (search) {
    query += ` AND (v.title LIKE ? OR v.description LIKE ? OR u.username LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  query += ` ORDER BY v.created_at DESC LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), parseInt(offset));

  const videos = db.prepare(query).all(...params);
  res.json({ videos });
});

app.get('/api/videos/all', (req, res) => {
  const { search, page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;
  let query = `
    SELECT v.*, u.display_name, u.avatar, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count
    FROM videos v JOIN users u ON v.user_id=u.id
    WHERE v.visibility='public'
  `;
  const params = [];
  if (search) {
    query += ` AND (v.title LIKE ? OR v.description LIKE ? OR u.username LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  query += ` ORDER BY v.created_at DESC LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), parseInt(offset));

  const videos = db.prepare(query).all(...params);
  res.json({ videos });
});

app.get('/api/videos/:id', (req, res) => {
  const video = db.prepare(`
    SELECT v.*, u.display_name, u.avatar, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count,
    (SELECT COUNT(*) FROM follows WHERE following_id=v.user_id) as channel_followers
    FROM videos v JOIN users u ON v.user_id=u.id
    WHERE v.id=?
  `).get(req.params.id);

  if (!video) return res.status(404).json({ error: 'Video not found' });

  // Visibility check
  if (video.visibility === 'private' && video.user_id !== req.session.userId)
    return res.status(403).json({ error: 'This video is private' });

  if (video.visibility === 'followers_only') {
    if (!req.session.userId) return res.status(403).json({ error: 'Login required' });
    const isFollower = db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?')
      .get(req.session.userId, video.user_id);
    if (!isFollower && video.user_id !== req.session.userId)
      return res.status(403).json({ error: 'Followers only' });
  }

  // Increment views
  db.prepare('UPDATE videos SET views=views+1 WHERE id=?').run(req.params.id);

  let isLiked = false;
  let isFollowing = false;
  if (req.session.userId) {
    isLiked = !!db.prepare('SELECT id FROM likes WHERE user_id=? AND video_id=?')
      .get(req.session.userId, req.params.id);
    isFollowing = !!db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?')
      .get(req.session.userId, video.user_id);
  }

  const comments = db.prepare(`
    SELECT c.*, u.display_name, u.avatar, u.username
    FROM comments c JOIN users u ON c.user_id=u.id
    WHERE c.video_id=? ORDER BY c.created_at DESC
  `).all(req.params.id);

  res.json({ video: { ...video, views: video.views + 1 }, isLiked, isFollowing, comments });
});

app.delete('/api/videos/:id', requireAuth, (req, res) => {
  const video = db.prepare('SELECT * FROM videos WHERE id=?').get(req.params.id);
  if (!video) return res.status(404).json({ error: 'Not found' });
  if (video.user_id !== req.session.userId) return res.status(403).json({ error: 'Forbidden' });

  // Delete files
  const videoFile = path.join(__dirname, 'public', video.filename);
  if (fs.existsSync(videoFile)) fs.unlinkSync(videoFile);
  if (video.thumbnail) {
    const thumbFile = path.join(__dirname, 'public', video.thumbnail);
    if (fs.existsSync(thumbFile)) fs.unlinkSync(thumbFile);
  }

  db.prepare('DELETE FROM likes WHERE video_id=?').run(req.params.id);
  db.prepare('DELETE FROM comments WHERE video_id=?').run(req.params.id);
  db.prepare('DELETE FROM reports WHERE video_id=?').run(req.params.id);
  db.prepare('DELETE FROM videos WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ─── API: Likes ───────────────────────────────────────────────────────────────
app.post('/api/videos/:id/like', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT id FROM likes WHERE user_id=? AND video_id=?')
    .get(req.session.userId, req.params.id);
  if (existing) {
    db.prepare('DELETE FROM likes WHERE user_id=? AND video_id=?').run(req.session.userId, req.params.id);
    res.json({ liked: false });
  } else {
    db.prepare('INSERT INTO likes (id,user_id,video_id) VALUES (?,?,?)')
      .run(uuidv4(), req.session.userId, req.params.id);
    res.json({ liked: true });
  }
});

app.get('/api/liked-videos', requireAuth, (req, res) => {
  const videos = db.prepare(`
    SELECT v.*, u.display_name, u.avatar, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count
    FROM likes l
    JOIN videos v ON l.video_id=v.id
    JOIN users u ON v.user_id=u.id
    WHERE l.user_id=?
    ORDER BY l.created_at DESC
  `).all(req.session.userId);
  res.json({ videos });
});

// ─── API: Comments ────────────────────────────────────────────────────────────
app.post('/api/videos/:id/comments', requireAuth, (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  const id = uuidv4();
  db.prepare('INSERT INTO comments (id,user_id,video_id,content) VALUES (?,?,?,?)')
    .run(id, req.session.userId, req.params.id, content.trim());
  const comment = db.prepare(`
    SELECT c.*, u.display_name, u.avatar, u.username
    FROM comments c JOIN users u ON c.user_id=u.id WHERE c.id=?
  `).get(id);
  res.json({ comment });
});

app.delete('/api/comments/:id', requireAuth, (req, res) => {
  const comment = db.prepare('SELECT * FROM comments WHERE id=?').get(req.params.id);
  if (!comment) return res.status(404).json({ error: 'Not found' });
  if (comment.user_id !== req.session.userId) return res.status(403).json({ error: 'Forbidden' });
  db.prepare('DELETE FROM comments WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ─── API: Follows ─────────────────────────────────────────────────────────────
app.post('/api/users/:id/follow', requireAuth, (req, res) => {
  if (req.params.id === req.session.userId) return res.status(400).json({ error: "Can't follow yourself" });
  const existing = db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?')
    .get(req.session.userId, req.params.id);
  if (existing) {
    db.prepare('DELETE FROM follows WHERE follower_id=? AND following_id=?').run(req.session.userId, req.params.id);
    res.json({ following: false });
  } else {
    db.prepare('INSERT INTO follows (id,follower_id,following_id) VALUES (?,?,?)')
      .run(uuidv4(), req.session.userId, req.params.id);
    res.json({ following: true });
  }
});

app.get('/api/feed', requireAuth, (req, res) => {
  const videos = db.prepare(`
    SELECT v.*, u.display_name, u.avatar, u.username,
    (SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count
    FROM videos v JOIN users u ON v.user_id=u.id
    WHERE v.user_id IN (SELECT following_id FROM follows WHERE follower_id=?)
    AND v.visibility='public' AND v.rating != '18+'
    ORDER BY v.created_at DESC LIMIT 50
  `).all(req.session.userId);
  res.json({ videos });
});

// ─── API: Reports ─────────────────────────────────────────────────────────────
app.post('/api/videos/:id/report', requireAuth, (req, res) => {
  const { reason } = req.body;
  if (!reason) return res.status(400).json({ error: 'Reason required' });
  db.prepare('INSERT INTO reports (id,reporter_id,video_id,reason) VALUES (?,?,?,?)')
    .run(uuidv4(), req.session.userId, req.params.id, reason);
  res.json({ success: true });
});

// ─── Serve Frontend ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🎬 Doov running at http://localhost:${PORT}`);
});
