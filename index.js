
import express from 'express'
import cors from 'cors'
import sqlite3 from 'sqlite3'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(cors())
app.use(express.json())

const dbPath = path.join(__dirname, 'cashlot.db')
const db = new sqlite3.Database(dbPath)

// Initialize tables
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT "user", coins INTEGER DEFAULT 0)')
  db.run('CREATE TABLE IF NOT EXISTS offers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, type TEXT, payout TEXT)')
  db.run('CREATE TABLE IF NOT EXISTS leaderboard (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, earned INTEGER)')
  db.run('CREATE TABLE IF NOT EXISTS payouts (id INTEGER PRIMARY KEY AUTOINCREMENT, method TEXT, amount INTEGER, status TEXT)')
  db.run('CREATE TABLE IF NOT EXISTS referrals (id INTEGER PRIMARY KEY AUTOINCREMENT, referrer TEXT, referee TEXT, bonus INTEGER)')

  // seed admin
  db.get('SELECT * FROM users WHERE email=?', ['admin@cashlot.gg'], (err, row) => {
    if (!row) {
      db.run('INSERT INTO users (email, password, role, coins) VALUES (?,?,?,?)', ['admin@cashlot.gg','admin123','admin',100000])
    }
  })
  // seed offers
  db.get('SELECT COUNT(*) AS c FROM offers', (err, row) => {
    if (row && row.c === 0) {
      const offers = [
        ['BitLabs Surveys','Surveys','op til 2,500 coins'],
        ['AdGate Media','Offerwall','op til 10,000 coins'],
        ['CPX Research','Surveys','op til 3,000 coins'],
        ['Lootably','Offerwall','op til 8,000 coins'],
        ['RevU Apps','Apps','op til 15,000 coins']
      ]
      offers.forEach(o => db.run('INSERT INTO offers (name,type,payout) VALUES (?,?,?)', o))
    }
  })
  // seed leaderboard
  db.get('SELECT COUNT(*) AS c FROM leaderboard', (err, row) => {
    if (row && row.c === 0) {
      const lb = [
        ['@mads',48250],['@sara',41190],['@niko',36210],['@clara',28560],['@leo',21050]
      ]
      lb.forEach(l => db.run('INSERT INTO leaderboard (user, earned) VALUES (?,?)', l))
    }
  })
})

// Auth (demo)
app.post('/api/auth/signup', (req,res)=>{
  const { email, password } = req.body
  if(!email || !password) return res.status(400).json({error:'missing fields'})
  db.run('INSERT INTO users (email,password,role,coins) VALUES (?,?,?,?)', [email,password,'user',0], function(err){
    if(err) return res.status(400).json({error:'user exists or db error'})
    res.json({ token: 'demo-'+this.lastID, user: { id:this.lastID, email, role:'user' } })
  })
})

app.post('/api/auth/login', (req,res)=>{
  const { email, password } = req.body
  db.get('SELECT * FROM users WHERE email=? AND password=?', [email,password], (err,row)=>{
    if(!row) return res.status(401).json({error:'invalid credentials'})
    const isAdmin = row.role === 'admin'
    res.json({ token: isAdmin ? 'admin-token' : 'user-token', user: { id:row.id, email:row.email, role:row.role } })
  })
})

// Public endpoints
app.get('/api/offers', (req,res)=>{
  db.all('SELECT * FROM offers', (err, rows)=> res.json(rows || []))
})
app.get('/api/leaderboard', (req,res)=>{
  db.all('SELECT user, earned FROM leaderboard ORDER BY earned DESC', (err, rows)=> res.json(rows || []))
})
app.get('/api/payouts', (req,res)=>{
  db.all('SELECT * FROM payouts', (err, rows)=> res.json(rows || []))
})
app.get('/api/referrals', (req,res)=>{
  db.all('SELECT * FROM referrals', (err, rows)=> res.json(rows || []))
})

// Admin (very simple guard)
function requireAdmin(req,res,next){
  const token = req.headers['x-token']
  if(token === 'admin-token') return next()
  res.status(403).json({error:'admin only'})
}
app.get('/api/admin/users', requireAdmin, (req,res)=>{
  db.all('SELECT id,email,role,coins FROM users', (err, rows)=> res.json(rows || []))
})

const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log('Cashlot backend on port ' + PORT))

