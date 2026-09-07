require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('./doov.db');
const dbGet = (sql, params=[]) => new Promise((res,rej) => db.get(sql, params, (e,r) => e ? rej(e) : res(r)));
const dbAll = (sql, params=[]) => new Promise((res,rej) => db.all(sql, params, (e,r) => e ? rej(e) : res(r)));
const dbRun = (sql, params=[]) => new Promise((res,rej) => db.run(sql, params, function(e){ e ? rej(e) : res(this); }));

db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, display_name TEXT NOT NULL, avatar TEXT DEFAULT NULL, bio TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS videos (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL, description TEXT DEFAULT '', filename TEXT NOT NULL, thumbnail TEXT DEFAULT NULL, rating TEXT DEFAULT 'all', visibility TEXT DEFAULT 'public', views INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS likes (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, video_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, video_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, video_id TEXT NOT NULL, content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS follows (id TEXT PRIMARY KEY, follower_id TEXT NOT NULL, following_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(follower_id, following_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, reporter_id TEXT NOT NULL, video_id TEXT NOT NULL, reason TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

['public/uploads/avatars','public/uploads/videos','public/uploads/thumbnails'].forEach(d => { if(!fs.existsSync(d)) fs.mkdirSync(d,{recursive:true}); });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({ secret: process.env.SESSION_SECRET||'doov_secret_2024', resave:false, saveUninitialized:false, cookie:{maxAge:7*24*60*60*1000} }));

const requireAuth = (req,res,next) => { if(!req.session.userId) return res.status(401).json({error:'Unauthorized'}); next(); };

app.post('/api/register', async (req,res) => {
  try {
    const {username,email,password,display_name} = req.body;
    if(!username||!email||!password||!display_name) return res.status(400).json({error:'All fields required'});
    if(password.length<6) return res.status(400).json({error:'Password must be at least 6 characters'});
    const hash = await bcrypt.hash(password,10);
    const id = uuidv4();
    await dbRun('INSERT INTO users (id,username,email,password,display_name) VALUES (?,?,?,?,?)',[id,username.toLowerCase(),email.toLowerCase(),hash,display_name]);
    req.session.userId = id;
    const user = await dbGet('SELECT id,username,email,display_name,avatar,bio FROM users WHERE id=?',[id]);
    res.json({success:true,user});
  } catch(e) { e.message.includes('UNIQUE') ? res.status(400).json({error:'Username or email already taken'}) : res.status(500).json({error:'Server error'}); }
});

app.post('/api/login', async (req,res) => {
  try {
    const {username,password} = req.body;
    const user = await dbGet('SELECT * FROM users WHERE username=? OR email=?',[username.toLowerCase(),username.toLowerCase()]);
    if(!user) return res.status(401).json({error:'Invalid credentials'});
    const ok = await bcrypt.compare(password,user.password);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    req.session.userId = user.id;
    res.json({success:true,user:{id:user.id,username:user.username,display_name:user.display_name,avatar:user.avatar}});
  } catch(e) { res.status(500).json({error:'Server error'}); }
});

app.post('/api/logout', (req,res) => { req.session.destroy(); res.json({success:true}); });
app.get('/api/me', async (req,res) => { if(!req.session.userId) return res.json({user:null}); const user=await dbGet('SELECT id,username,email,display_name,avatar,bio FROM users WHERE id=?',[req.session.userId]); res.json({user}); });

app.post('/api/profile/avatar', requireAuth, multer({storage:multer.diskStorage({destination:'./public/uploads/avatars/',filename:(req,file,cb)=>cb(null,uuidv4()+path.extname(file.originalname))}),limits:{fileSize:10*1024*1024}}).single('avatar'), async (req,res) => {
  if(!req.file) return res.status(400).json({error:'No file'});
  const avatarPath='/uploads/avatars/'+req.file.filename;
  await dbRun('UPDATE users SET avatar=? WHERE id=?',[avatarPath,req.session.userId]);
  res.json({success:true,avatar:avatarPath});
});

app.post('/api/profile/update', requireAuth, async (req,res) => {
  const {display_name,bio}=req.body;
  await dbRun('UPDATE users SET display_name=?,bio=? WHERE id=?',[display_name,bio,req.session.userId]);
  res.json({success:true});
});

app.get('/api/profile/:username', async (req,res) => {
  try {
    const user=await dbGet('SELECT id,username,display_name,avatar,bio,created_at FROM users WHERE username=?',[req.params.username]);
    if(!user) return res.status(404).json({error:'User not found'});
    const videos=await dbAll(`SELECT v.*,u.display_name,u.avatar,u.username,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count FROM videos v JOIN users u ON v.user_id=u.id WHERE v.user_id=? AND v.visibility='public' ORDER BY v.created_at DESC`,[user.id]);
    const r1=await dbGet('SELECT COUNT(*) as c FROM follows WHERE following_id=?',[user.id]);
    const r2=await dbGet('SELECT COUNT(*) as c FROM follows WHERE follower_id=?',[user.id]);
    let isFollowing=false;
    if(req.session.userId) isFollowing=!!(await dbGet('SELECT id FROM follows WHERE follower_id=? AND following_id=?',[req.session.userId,user.id]));
    res.json({user,videos,followerCount:r1.c,followingCount:r2.c,isFollowing});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/videos/create', requireAuth, (req,res) => {
  multer({storage:multer.diskStorage({destination:(req,file,cb)=>cb(null,file.fieldname==='video'?'./public/uploads/videos/':'./public/uploads/thumbnails/'),filename:(req,file,cb)=>cb(null,uuidv4()+path.extname(file.originalname))}),limits:{fileSize:500*1024*1024}}).fields([{name:'video',maxCount:1},{name:'thumbnail',maxCount:1}])(req,res,async(err)=>{
    if(err) return res.status(400).json({error:err.message});
    const {title,description,rating,visibility}=req.body;
    if(!title) return res.status(400).json({error:'Title required'});
    if(!req.files?.video) return res.status(400).json({error:'No video file'});
    const id=uuidv4();
    const videoPath='/uploads/videos/'+req.files.video[0].filename;
    const thumbPath=req.files?.thumbnail?'/uploads/thumbnails/'+req.files.thumbnail[0].filename:null;
    await dbRun(`INSERT INTO videos (id,user_id,title,description,filename,thumbnail,rating,visibility) VALUES (?,?,?,?,?,?,?,?)`,[id,req.session.userId,title,description||'',videoPath,thumbPath,rating||'all',visibility||'public']);
    res.json({success:true,videoId:id});
  });
});

app.get('/api/videos', async (req,res) => {
  try {
    const {search,page=1,limit=20}=req.query; const offset=(page-1)*limit;
    let sql=`SELECT v.*,u.display_name,u.avatar,u.username,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count FROM videos v JOIN users u ON v.user_id=u.id WHERE v.visibility='public' AND v.rating != '18+'`;
    const params=[];
    if(search){sql+=` AND (v.title LIKE ? OR v.description LIKE ? OR u.username LIKE ?)`;params.push(`%${search}%`,`%${search}%`,`%${search}%`);}
    sql+=` ORDER BY v.created_at DESC LIMIT ? OFFSET ?`; params.push(parseInt(limit),parseInt(offset));
    res.json({videos:await dbAll(sql,params)});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/videos/all', async (req,res) => {
  try {
    const {search,page=1,limit=20}=req.query; const offset=(page-1)*limit;
    let sql=`SELECT v.*,u.display_name,u.avatar,u.username,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count FROM videos v JOIN users u ON v.user_id=u.id WHERE v.visibility='public'`;
    const params=[];
    if(search){sql+=` AND (v.title LIKE ? OR v.description LIKE ? OR u.username LIKE ?)`;params.push(`%${search}%`,`%${search}%`,`%${search}%`);}
    sql+=` ORDER BY v.created_at DESC LIMIT ? OFFSET ?`; params.push(parseInt(limit),parseInt(offset));
    res.json({videos:await dbAll(sql,params)});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/videos/:id', async (req,res) => {
  try {
    const video=await dbGet(`SELECT v.*,u.display_name,u.avatar,u.username,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count,(SELECT COUNT(*) FROM follows WHERE following_id=v.user_id) as channel_followers FROM videos v JOIN users u ON v.user_id=u.id WHERE v.id=?`,[req.params.id]);
    if(!video) return res.status(404).json({error:'Video not found'});
    if(video.visibility==='private'&&video.user_id!==req.session.userId) return res.status(403).json({error:'This video is private'});
    if(video.visibility==='followers_only'){
      if(!req.session.userId) return res.status(403).json({error:'Login required'});
      const f=await dbGet('SELECT id FROM follows WHERE follower_id=? AND following_id=?',[req.session.userId,video.user_id]);
      if(!f&&video.user_id!==req.session.userId) return res.status(403).json({error:'Followers only'});
    }
    await dbRun('UPDATE videos SET views=views+1 WHERE id=?',[req.params.id]);
    let isLiked=false,isFollowing=false;
    if(req.session.userId){
      isLiked=!!(await dbGet('SELECT id FROM likes WHERE user_id=? AND video_id=?',[req.session.userId,req.params.id]));
      isFollowing=!!(await dbGet('SELECT id FROM follows WHERE follower_id=? AND following_id=?',[req.session.userId,video.user_id]));
    }
    const comments=await dbAll(`SELECT c.*,u.display_name,u.avatar,u.username FROM comments c JOIN users u ON c.user_id=u.id WHERE c.video_id=? ORDER BY c.created_at DESC`,[req.params.id]);
    res.json({video:{...video,views:video.views+1},isLiked,isFollowing,comments});
  } catch(e){res.status(500).json({error:e.message});}
});

app.delete('/api/videos/:id', requireAuth, async (req,res) => {
  try {
    const video=await dbGet('SELECT * FROM videos WHERE id=?',[req.params.id]);
    if(!video) return res.status(404).json({error:'Not found'});
    if(video.user_id!==req.session.userId) return res.status(403).json({error:'Forbidden'});
    [video.filename,video.thumbnail].filter(Boolean).forEach(f=>{const fp=path.join(__dirname,'public',f);if(fs.existsSync(fp))fs.unlinkSync(fp);});
    await dbRun('DELETE FROM likes WHERE video_id=?',[req.params.id]);
    await dbRun('DELETE FROM comments WHERE video_id=?',[req.params.id]);
    await dbRun('DELETE FROM reports WHERE video_id=?',[req.params.id]);
    await dbRun('DELETE FROM videos WHERE id=?',[req.params.id]);
    res.json({success:true});
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/videos/:id/like', requireAuth, async (req,res) => {
  const ex=await dbGet('SELECT id FROM likes WHERE user_id=? AND video_id=?',[req.session.userId,req.params.id]);
  if(ex){await dbRun('DELETE FROM likes WHERE user_id=? AND video_id=?',[req.session.userId,req.params.id]);res.json({liked:false});}
  else{await dbRun('INSERT INTO likes (id,user_id,video_id) VALUES (?,?,?)',[uuidv4(),req.session.userId,req.params.id]);res.json({liked:true});}
});

app.get('/api/liked-videos', requireAuth, async (req,res) => {
  const videos=await dbAll(`SELECT v.*,u.display_name,u.avatar,u.username,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count FROM likes l JOIN videos v ON l.video_id=v.id JOIN users u ON v.user_id=u.id WHERE l.user_id=? ORDER BY l.created_at DESC`,[req.session.userId]);
  res.json({videos});
});

app.post('/api/videos/:id/comments', requireAuth, async (req,res) => {
  const {content}=req.body;
  if(!content||!content.trim()) return res.status(400).json({error:'Empty comment'});
  const id=uuidv4();
  await dbRun('INSERT INTO comments (id,user_id,video_id,content) VALUES (?,?,?,?)',[id,req.session.userId,req.params.id,content.trim()]);
  const comment=await dbGet(`SELECT c.*,u.display_name,u.avatar,u.username FROM comments c JOIN users u ON c.user_id=u.id WHERE c.id=?`,[id]);
  res.json({comment});
});

app.delete('/api/comments/:id', requireAuth, async (req,res) => {
  const c=await dbGet('SELECT * FROM comments WHERE id=?',[req.params.id]);
  if(!c) return res.status(404).json({error:'Not found'});
  if(c.user_id!==req.session.userId) return res.status(403).json({error:'Forbidden'});
  await dbRun('DELETE FROM comments WHERE id=?',[req.params.id]);
  res.json({success:true});
});

app.post('/api/users/:id/follow', requireAuth, async (req,res) => {
  if(req.params.id===req.session.userId) return res.status(400).json({error:"Can't follow yourself"});
  const ex=await dbGet('SELECT id FROM follows WHERE follower_id=? AND following_id=?',[req.session.userId,req.params.id]);
  if(ex){await dbRun('DELETE FROM follows WHERE follower_id=? AND following_id=?',[req.session.userId,req.params.id]);res.json({following:false});}
  else{await dbRun('INSERT INTO follows (id,follower_id,following_id) VALUES (?,?,?)',[uuidv4(),req.session.userId,req.params.id]);res.json({following:true});}
});

app.get('/api/feed', requireAuth, async (req,res) => {
  const videos=await dbAll(`SELECT v.*,u.display_name,u.avatar,u.username,(SELECT COUNT(*) FROM likes WHERE video_id=v.id) as like_count FROM videos v JOIN users u ON v.user_id=u.id WHERE v.user_id IN (SELECT following_id FROM follows WHERE follower_id=?) AND v.visibility='public' AND v.rating != '18+' ORDER BY v.created_at DESC LIMIT 50`,[req.session.userId]);
  res.json({videos});
});

app.post('/api/videos/:id/report', requireAuth, async (req,res) => {
  const {reason}=req.body;
  if(!reason) return res.status(400).json({error:'Reason required'});
  await dbRun('INSERT INTO reports (id,reporter_id,video_id,reason) VALUES (?,?,?,?)',[uuidv4(),req.session.userId,req.params.id,reason]);
  res.json({success:true});
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, () => console.log(`🎬 Doov running at http://localhost:${PORT}`));

