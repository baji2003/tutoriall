const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()
const PORT = 3000
const SECRET = 'your_secret_key'

app.use(cors())
app.use(express.json())

// DB Setup
const db = new sqlite3.Database('./ecommerce.db')

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`)
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL,
    category TEXT
  )`)
  db.run(`CREATE TABLE IF NOT EXISTS cart (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    productId INTEGER,
    quantity INTEGER
  )`)
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    orderDate TEXT,
    items TEXT
  )`)
})

// Middleware
function auth(req, res, next) {
  const token = req.headers['authorization']
  if (!token) return res.status(403).send('Token missing')
  try {
    const decoded = jwt.verify(token.split(' ')[1], SECRET)
    req.user = decoded
    next()
  } catch {
    return res.status(401).send('Invalid token')
  }
}

function role(requiredRole) {
  return (req, res, next) => {
    if (req.user.role !== requiredRole)
      return res.status(403).send('Access denied')
    next()
  }
}

// Routes

// Register
app.post('/auth/register', async (req, res) => {
  const {username, password, role} = req.body
  const hash = await bcrypt.hash(password, 10)
  db.run(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
    [username, hash, role || 'customer'],
    err => {
      if (err) return res.status(400).send('User already exists')
      res.send('User registered')
    },
  )
})

// Login
app.post('/auth/login', (req, res) => {
  const {username, password} = req.body
  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, user) => {
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials')
      }
      const token = jwt.sign({id: user.id, role: user.role}, SECRET)
      res.json({token})
    },
  )
})

// Product Routes
app.get('/products', (req, res) => {
  const {search = '', category = '', page = 1, limit = 10} = req.query
  const offset = (page - 1) * limit
  db.all(
    `SELECT * FROM products WHERE name LIKE ? AND category LIKE ? LIMIT ? OFFSET ?`,
    [`%${search}%`, `%${category}%`, limit, offset],
    (err, rows) => {
      if (err) return res.status(500).send('Error fetching products')
      res.json(rows)
    },
  )
})

app.post('/products', auth, role('admin'), (req, res) => {
  const {name, description, price, category} = req.body
  db.run(
    'INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)',
    [name, description, price, category],
    function (err) {
      if (err) return res.status(500).send('Error adding product')
      res.send({id: this.lastID})
    },
  )
})

app.put('/products/:id', auth, role('admin'), (req, res) => {
  const {name, description, price, category} = req.body
  db.run(
    'UPDATE products SET name=?, description=?, price=?, category=? WHERE id=?',
    [name, description, price, category, req.params.id],
    err => {
      if (err) return res.status(500).send('Error updating product')
      res.send('Product updated')
    },
  )
})

app.delete('/products/:id', auth, role('admin'), (req, res) => {
  db.run('DELETE FROM products WHERE id=?', [req.params.id], err => {
    if (err) return res.status(500).send('Error deleting product')
    res.send('Product deleted')
  })
})

// Cart Routes
app.post('/cart', auth, (req, res) => {
  const {productId, quantity} = req.body
  db.run(
    'INSERT INTO cart (userId, productId, quantity) VALUES (?, ?, ?)',
    [req.user.id, productId, quantity],
    err => {
      if (err) return res.status(500).send('Error adding to cart')
      res.send('Added to cart')
    },
  )
})

app.get('/cart', auth, (req, res) => {
  db.all(
    'SELECT cart.id, products.name, cart.quantity FROM cart JOIN products ON cart.productId = products.id WHERE userId = ?',
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).send('Error fetching cart')
      res.json(rows)
    },
  )
})

app.delete('/cart/:id', auth, (req, res) => {
  db.run(
    'DELETE FROM cart WHERE id=? AND userId=?',
    [req.params.id, req.user.id],
    err => {
      if (err) return res.status(500).send('Error removing item')
      res.send('Item removed')
    },
  )
})

// Order Route
app.post('/orders', auth, (req, res) => {
  db.all('SELECT * FROM cart WHERE userId=?', [req.user.id], (err, items) => {
    if (err || items.length === 0)
      return res.status(400).send('Cart empty or error')
    const orderDate = new Date().toISOString()
    const itemList = JSON.stringify(items)
    db.run(
      'INSERT INTO orders (userId, orderDate, items) VALUES (?, ?, ?)',
      [req.user.id, orderDate, itemList],
      function (err) {
        if (err) return res.status(500).send('Error placing order')
        db.run('DELETE FROM cart WHERE userId=?', [req.user.id])
        res.send({orderId: this.lastID})
      },
    )
  })
})

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`)
})
