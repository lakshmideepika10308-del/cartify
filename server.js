require('dotenv').config();
/* CARTIFY - Shopping Made Simple. Single-file full-stack app (Express + MySQL + vanilla JS)
   Run:  npm init -y && npm i express mysql2 bcryptjs && node cartify.js
   Env (optional): DB_HOST DB_USER DB_PASSWORD DB_NAME PORT
   Admin login: admin@cartify.com / Admin@123  (change after first login) */
const express = require('express'), mysql = require('mysql2/promise'), bcrypt = require('bcryptjs'), crypto = require('crypto');
const C = { host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER || 'root', password: process.env.DB_PASSWORD || '' };
const DBN = process.env.DB_NAME || 'cartify_db', PORT = process.env.PORT || 3000;
let db; const sessions = new Map(), tries = new Map();
const app = express(); app.use(express.json({ limit: '1mb' }));
const A = f => (q, s) => f(q, s).catch(e => { console.error(e); s.status(500).json({ error: 'Server error' }); });
const q = async (sql, p) => (await db.query(sql, p))[0];
// ---------- auth middleware ----------
app.use((req, res, next) => {
  const m = /(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie || ''); req.user = m && sessions.get(m[1]) || null; req.sid = m && m[1]; next();
});
const auth = (q, s, n) => q.user ? n() : s.status(401).json({ error: 'Please login' });
const admin = (q, s, n) => q.user && q.user.role === 'admin' ? n() : s.status(403).json({ error: 'Admin only' });
const login = (res, u) => { const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, { id: u.id, name: u.name, email: u.email, role: u.role }); res.setHeader('Set-Cookie', 'sid=' + t + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800'); };
const P = 'SELECT p.*, ROUND(p.price*(1-p.discount_percent/100),2) sale_price, c.name category FROM products p JOIN categories c ON c.id=p.category_id';
// ---------- AUTH ----------
app.post('/api/auth/register', A(async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Valid name and email required' });
  if (!/^[0-9+\- ]{7,15}$/.test(phone || '')) return res.status(400).json({ error: 'Valid phone required' });
  if (!/^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(password || '')) return res.status(400).json({ error: 'Password: 8+ chars with letters and numbers' });
  if ((await q('SELECT id FROM users WHERE email=?', [email])).length) return res.status(409).json({ error: 'Email already registered' });
  const r = (await db.query('INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)', [name, email, phone, await bcrypt.hash(password, 10)]))[0];
  const u = { id: r.insertId, name, email, role: 'customer' }; login(res, u); res.json({ user: u });
}));
app.post('/api/auth/login', A(async (req, res) => {
  const k = req.ip, t = tries.get(k) || { n: 0, at: Date.now() };
  if (Date.now() - t.at > 9e5) { t.n = 0; t.at = Date.now(); }
  if (t.n >= 10) return res.status(429).json({ error: 'Too many attempts. Try later.' });
  const u = (await q('SELECT * FROM users WHERE email=?', [req.body.email || '']))[0];
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash))) { t.n++; tries.set(k, t); return res.status(401).json({ error: 'Invalid email or password' }); }
  if (!u.is_active) return res.status(403).json({ error: 'Account disabled' });
  login(res, u); res.json({ user: { id: u.id, name: u.name, email: u.email, role: u.role } });
}));
app.post('/api/auth/logout', (req, res) => { sessions.delete(req.sid); res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); res.json({ ok: 1 }); });
app.get('/api/auth/me', (req, res) => req.user ? res.json({ user: req.user }) : res.status(401).json({ error: 'Not logged in' }));
// ---------- CATEGORIES ----------
app.get('/api/categories', A(async (_, res) => res.json(await q('SELECT c.*, (SELECT COUNT(*) FROM products WHERE category_id=c.id) products FROM categories c ORDER BY id'))));
app.post('/api/categories', auth, admin, A(async (req, res) => {
  if (!req.body.name) return res.status(400).json({ error: 'Name required' });
  try { const r = (await db.query('INSERT INTO categories(name,image) VALUES(?,?)', [req.body.name, req.body.image || '']))[0]; res.json({ id: r.insertId }); } catch (e) { res.status(409).json({ error: 'Category exists' }); }
}));
app.put('/api/categories/:id', auth, admin, A(async (req, res) => { await q('UPDATE categories SET name=?,image=? WHERE id=?', [req.body.name, req.body.image || '', req.params.id]); res.json({ ok: 1 }); }));
app.delete('/api/categories/:id', auth, admin, A(async (req, res) => {
  if ((await q('SELECT id FROM products WHERE category_id=?', [req.params.id])).length) return res.status(400).json({ error: 'Category has products' });
  await q('DELETE FROM categories WHERE id=?', [req.params.id]); res.json({ ok: 1 });
}));
// ---------- PRODUCTS ----------
app.get('/api/products', A(async (req, res) => {
  const { search, category, min, max, sort, limit } = req.query, page = Math.max(1, +req.query.page || 1), lim = Math.min(+limit || 12, 50);
  const w = ['1=1'], p = [];
  if (search) { w.push('(p.name LIKE ? OR p.description LIKE ?)'); p.push('%' + search + '%', '%' + search + '%'); }
  if (category) { w.push('p.category_id=?'); p.push(+category); }
  if (min) { w.push('ROUND(p.price*(1-p.discount_percent/100),2)>=?'); p.push(+min); }
  if (max) { w.push('ROUND(p.price*(1-p.discount_percent/100),2)<=?'); p.push(+max); }
  const o = { price_asc: 'sale_price ASC', price_desc: 'sale_price DESC', new: 'p.id DESC', popular: 'p.sold DESC', discount: 'p.discount_percent DESC', rating: 'p.rating DESC' }[sort] || 'p.id ASC';
  const total = (await q('SELECT COUNT(*) n FROM products p WHERE ' + w.join(' AND '), p))[0].n;
  const items = await q(P + ' WHERE ' + w.join(' AND ') + ' ORDER BY ' + o + ' LIMIT ? OFFSET ?', [...p, lim, (page - 1) * lim]);
  res.json({ items, total, pages: Math.ceil(total / lim) });
}));
app.get('/api/products/:id', A(async (req, res) => {
  const p = (await q(P + ' WHERE p.id=?', [req.params.id]))[0]; if (!p) return res.status(404).json({ error: 'Not found' });
  p.related = await q(P + ' WHERE p.category_id=? AND p.id<>? LIMIT 4', [p.category_id, p.id]); res.json(p);
}));
const pv = b => b.name && +b.price > 0 && +b.category_id && +b.discount_percent >= 0 && +b.discount_percent < 100 && +b.stock >= 0;
app.post('/api/products', auth, admin, A(async (req, res) => {
  const b = req.body; if (!pv(b)) return res.status(400).json({ error: 'Invalid product data' });
  const r = (await db.query('INSERT INTO products(name,description,price,discount_percent,stock,image,category_id) VALUES(?,?,?,?,?,?,?)', [b.name, b.description || '', b.price, b.discount_percent, b.stock, b.image || '', b.category_id]))[0]; res.json({ id: r.insertId });
}));
app.put('/api/products/:id', auth, admin, A(async (req, res) => {
  const b = req.body; if (!pv(b)) return res.status(400).json({ error: 'Invalid product data' });
  await q('UPDATE products SET name=?,description=?,price=?,discount_percent=?,stock=?,image=?,category_id=? WHERE id=?', [b.name, b.description || '', b.price, b.discount_percent, b.stock, b.image || '', b.category_id, req.params.id]); res.json({ ok: 1 });
}));
app.delete('/api/products/:id', auth, admin, A(async (req, res) => { await q('DELETE FROM products WHERE id=?', [req.params.id]); res.json({ ok: 1 }); }));
// ---------- WISHLIST ----------
app.get('/api/wishlist', auth, A(async (req, res) => res.json(await q(P + ' JOIN wishlist w ON w.product_id=p.id WHERE w.user_id=? ORDER BY w.created_at DESC', [req.user.id]))));
app.post('/api/wishlist', auth, A(async (req, res) => { await q('INSERT IGNORE INTO wishlist(user_id,product_id) VALUES(?,?)', [req.user.id, +req.body.productId]); res.json({ ok: 1 }); }));
app.delete('/api/wishlist/:productId', auth, A(async (req, res) => { await q('DELETE FROM wishlist WHERE user_id=? AND product_id=?', [req.user.id, req.params.productId]); res.json({ ok: 1 }); }));
// ---------- CART ----------
const cartOf = async uid => { const items = await q('SELECT ci.id item_id, ci.quantity, p.id, p.name, p.image, p.stock, ROUND(p.price*(1-p.discount_percent/100),2) sale_price FROM cart_items ci JOIN products p ON p.id=ci.product_id WHERE ci.user_id=?', [uid]); const subtotal = items.reduce((a, i) => a + i.sale_price * i.quantity, 0); const shipping = !items.length || subtotal >= 999 ? 0 : 49; return { items, subtotal, shipping, total: subtotal + shipping }; };
app.get('/api/cart', auth, A(async (req, res) => res.json(await cartOf(req.user.id))));
app.post('/api/cart', auth, A(async (req, res) => {
  const pid = +req.body.productId, qty = Math.max(1, +req.body.quantity || 1), p = (await q('SELECT stock FROM products WHERE id=?', [pid]))[0];
  if (!p) return res.status(404).json({ error: 'Product not found' });
  const ex = (await q('SELECT quantity FROM cart_items WHERE user_id=? AND product_id=?', [req.user.id, pid]))[0];
  if ((ex ? ex.quantity : 0) + qty > p.stock) return res.status(400).json({ error: 'Only ' + p.stock + ' in stock' });
  await q('INSERT INTO cart_items(user_id,product_id,quantity) VALUES(?,?,?) ON DUPLICATE KEY UPDATE quantity=quantity+VALUES(quantity)', [req.user.id, pid, qty]); res.json(await cartOf(req.user.id));
}));
app.put('/api/cart/:itemId', auth, A(async (req, res) => {
  const it = (await q('SELECT ci.id, p.stock FROM cart_items ci JOIN products p ON p.id=ci.product_id WHERE ci.id=? AND ci.user_id=?', [req.params.itemId, req.user.id]))[0];
  if (!it) return res.status(404).json({ error: 'Not found' }); const n = +req.body.quantity;
  if (!(n >= 1)) return res.status(400).json({ error: 'Invalid quantity' }); if (n > it.stock) return res.status(400).json({ error: 'Only ' + it.stock + ' in stock' });
  await q('UPDATE cart_items SET quantity=? WHERE id=?', [n, it.id]); res.json(await cartOf(req.user.id));
}));
app.delete('/api/cart/:itemId', auth, A(async (req, res) => { await q('DELETE FROM cart_items WHERE id=? AND user_id=?', [req.params.itemId, req.user.id]); res.json(await cartOf(req.user.id)); }));
// ---------- ORDERS ----------
app.post('/api/orders', auth, A(async (req, res) => {
  const b = req.body; for (const k of ['name', 'email', 'phone', 'address', 'city', 'state', 'postal_code']) if (!b[k]) return res.status(400).json({ error: 'Missing ' + k });
  const c = await db.getConnection();
  try {
    await c.beginTransaction();
    const [items] = await c.query('SELECT ci.quantity, p.id, p.name, p.stock, ROUND(p.price*(1-p.discount_percent/100),2) price FROM cart_items ci JOIN products p ON p.id=ci.product_id WHERE ci.user_id=? FOR UPDATE', [req.user.id]);
    if (!items.length) throw new Error('Cart is empty');
    for (const i of items) if (i.quantity > i.stock) throw new Error(i.name + ': only ' + i.stock + ' left');
    const sub = items.reduce((a, i) => a + i.price * i.quantity, 0), ship = sub >= 999 ? 0 : 49;
    const [o] = await c.query('INSERT INTO orders(user_id,name,email,phone,address,city,state,postal_code,subtotal,shipping,total,payment_method) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', [req.user.id, b.name, b.email, b.phone, b.address, b.city, b.state, b.postal_code, sub, ship, sub + ship, 'COD']);
    for (const i of items) {
      await c.query('INSERT INTO order_items(order_id,product_id,name,price,quantity) VALUES(?,?,?,?,?)', [o.insertId, i.id, i.name, i.price, i.quantity]);
      await c.query('UPDATE products SET stock=stock-?, sold=sold+? WHERE id=?', [i.quantity, i.quantity, i.id]);
    }
    await c.query('DELETE FROM cart_items WHERE user_id=?', [req.user.id]); await c.commit(); res.json({ orderId: o.insertId });
  } catch (e) { await c.rollback(); res.status(400).json({ error: e.message }); } finally { c.release(); }
}));
const withItems = async os => { for (const o of os) o.items = await q('SELECT oi.*, p.image FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE order_id=?', [o.id]); return os; };
app.get('/api/orders', auth, A(async (req, res) => res.json(await withItems(await q('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC', [req.user.id])))));
app.get('/api/orders/:id', auth, A(async (req, res) => {
  const o = await withItems(await q('SELECT * FROM orders WHERE id=? AND (user_id=? OR ?)', [req.params.id, req.user.id, req.user.role === 'admin']));
  o[0] ? res.json(o[0]) : res.status(404).json({ error: 'Not found' });
}));
// ---------- ADMIN ----------
app.get('/api/admin/dashboard', auth, admin, A(async (_, res) => {
  const one = async s => Object.values((await q(s))[0])[0];
  res.json({
    products: await one('SELECT COUNT(*) FROM products'), customers: await one("SELECT COUNT(*) FROM users WHERE role='customer'"), orders: await one('SELECT COUNT(*) FROM orders'),
    revenue: await one("SELECT COALESCE(SUM(total),0) FROM orders WHERE status<>'Cancelled'"), pending: await one("SELECT COUNT(*) FROM orders WHERE status='Pending'"), lowStock: await one('SELECT COUNT(*) FROM products WHERE stock<10'),
    sales: await q("SELECT DATE_FORMAT(created_at,'%d %b') d, SUM(total) t FROM orders WHERE status<>'Cancelled' AND created_at>=DATE_SUB(CURDATE(),INTERVAL 6 DAY) GROUP BY DATE(created_at), d ORDER BY DATE(created_at)"),
    recentOrders: await q('SELECT id,name,total,status,created_at FROM orders ORDER BY id DESC LIMIT 5'), top: await q('SELECT name,sold FROM products ORDER BY sold DESC LIMIT 5'),
    recentCustomers: await q("SELECT name,email,created_at FROM users WHERE role='customer' ORDER BY id DESC LIMIT 5")
  });
}));
app.get('/api/admin/users', auth, admin, A(async (req, res) => res.json(await q("SELECT u.id,u.name,u.email,u.phone,u.is_active,u.created_at,(SELECT COUNT(*) FROM orders WHERE user_id=u.id) orders FROM users u WHERE role='customer' AND (u.name LIKE ? OR u.email LIKE ?) ORDER BY id DESC", ['%' + (req.query.search || '') + '%', '%' + (req.query.search || '') + '%']))));
app.put('/api/admin/users/:id/toggle', auth, admin, A(async (req, res) => { await q("UPDATE users SET is_active=1-is_active WHERE id=? AND role='customer'", [req.params.id]); res.json({ ok: 1 }); }));
app.get('/api/admin/orders', auth, admin, A(async (req, res) => res.json(await withItems(await q('SELECT * FROM orders' + (req.query.user ? ' WHERE user_id=' + (+req.query.user) : '') + ' ORDER BY id DESC')))));
const ST = ['Pending', 'Confirmed', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];
app.put('/api/admin/orders/:id/status', auth, admin, A(async (req, res) => {
  if (!ST.includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  const o = (await q('SELECT status FROM orders WHERE id=?', [req.params.id]))[0]; if (!o) return res.status(404).json({ error: 'Not found' });
  if (req.body.status === 'Cancelled' && o.status !== 'Cancelled') await q('UPDATE products p JOIN order_items oi ON oi.product_id=p.id SET p.stock=p.stock+oi.quantity WHERE oi.order_id=?', [req.params.id]); // restock
  await q('UPDATE orders SET status=? WHERE id=?', [req.body.status, req.params.id]); res.json({ ok: 1 });
}));
app.get('/api/admin/inventory', auth, admin, A(async (_, res) => res.json(await q('SELECT p.id,p.name,p.stock,c.name category FROM products p JOIN categories c ON c.id=p.category_id ORDER BY p.stock ASC'))));
app.put('/api/admin/inventory/:id', auth, admin, A(async (req, res) => { if (!(+req.body.stock >= 0)) return res.status(400).json({ error: 'Invalid stock' }); await q('UPDATE products SET stock=? WHERE id=?', [req.body.stock, req.params.id]); res.json({ ok: 1 }); }));
app.post('/api/newsletter/subscribe', A(async (req, res) => { if (!/^\S+@\S+\.\S+$/.test(req.body.email || '')) return res.status(400).json({ error: 'Valid email required' }); await q('INSERT IGNORE INTO newsletter_subscribers(email) VALUES(?)', [req.body.email]); res.json({ ok: 1 }); }));
// ---------- DB SETUP + SEED ----------
async function initDb() {
  const c = await mysql.createConnection(C); await c.query('CREATE DATABASE IF NOT EXISTS `' + DBN + '`'); await c.end();
  db = mysql.createPool({ ...C, database: DBN, decimalNumbers: true, connectionLimit: 10 });
  const T = [
    'users(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(100) NOT NULL,email VARCHAR(150) NOT NULL UNIQUE,phone VARCHAR(20),password_hash VARCHAR(100) NOT NULL,role ENUM("customer","admin") DEFAULT "customer",is_active TINYINT DEFAULT 1,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)',
    'categories(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(80) NOT NULL UNIQUE,image VARCHAR(300))',
    'products(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(150) NOT NULL,description TEXT,price DECIMAL(10,2) NOT NULL,discount_percent INT DEFAULT 0,stock INT DEFAULT 0,sold INT DEFAULT 0,rating DECIMAL(2,1) DEFAULT 4.5,image VARCHAR(300),category_id INT NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,INDEX(category_id),INDEX(name),FOREIGN KEY(category_id) REFERENCES categories(id))',
    'wishlist(id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,product_id INT NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,product_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE)',
    'cart_items(id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,product_id INT NOT NULL,quantity INT NOT NULL DEFAULT 1,UNIQUE(user_id,product_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE)',
    'orders(id INT AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,name VARCHAR(100),email VARCHAR(150),phone VARCHAR(20),address VARCHAR(255),city VARCHAR(80),state VARCHAR(80),postal_code VARCHAR(12),subtotal DECIMAL(10,2),shipping DECIMAL(10,2),total DECIMAL(10,2),payment_method VARCHAR(20),status ENUM("Pending","Confirmed","Processing","Shipped","Delivered","Cancelled") DEFAULT "Pending",created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,INDEX(user_id),FOREIGN KEY(user_id) REFERENCES users(id))',
    'order_items(id INT AUTO_INCREMENT PRIMARY KEY,order_id INT NOT NULL,product_id INT,name VARCHAR(150),price DECIMAL(10,2),quantity INT,FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL)',
    'newsletter_subscribers(id INT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(150) UNIQUE,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'
  ];
  for (const t of T) await db.query('CREATE TABLE IF NOT EXISTS ' + t);
  if (!(await q("SELECT id FROM users WHERE role='admin'")).length) await q('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)', ['Admin', 'admin@cartify.com', '0000000000', await bcrypt.hash('Admin@123', 10), 'admin']);
  if (!(await q('SELECT id FROM categories LIMIT 1')).length) {
    const cats = ['Fashion', 'Electronics', 'Home & Living', 'Beauty', 'Accessories', 'Lifestyle'];
    for (const c of cats) await q('INSERT INTO categories(name,image) VALUES(?,?)', [c, 'https://picsum.photos/seed/cat' + c.replace(/\W/g, '') + '/500/400']);
    const prods = [[1, 'Linen Button Shirt', 1799, 20, 'Breathable linen shirt in a relaxed fit.'], [1, 'Cocoa Knit Cardigan', 2499, 15, 'Soft chunky-knit cardigan for cosy days.'], [1, 'Wide-Leg Cotton Trousers', 1999, 10, 'High-waist trousers with a flowing drape.'], [1, 'Terracotta Midi Dress', 2899, 25, 'Easy midi dress in warm terracotta.'],
      [2, 'Wireless Earbuds Pro', 3499, 30, 'Noise-cancelling earbuds, 24h battery.'], [2, 'Smart Watch Series S', 5999, 20, 'Fitness tracking and AMOLED display.'], [2, 'Portable Bluetooth Speaker', 2499, 15, 'Rich sound in a pocket-sized body.'], [2, 'Mechanical Keyboard', 4299, 10, 'Hot-swappable keys, warm backlight.'],
      [3, 'Ceramic Dinner Set', 3299, 18, '12-piece handmade-look ceramic set.'], [3, 'Soy Wax Candle Trio', 899, 0, 'Vanilla, cedar and amber scents.'], [3, 'Woven Jute Rug', 3999, 22, 'Natural fibre rug for living rooms.'], [3, 'Oak Wall Shelf', 1599, 12, 'Floating shelf in solid oak finish.'],
      [4, 'Vitamin C Glow Serum', 1199, 25, 'Brightening serum with 15% vitamin C.'], [4, 'Rose Clay Face Mask', 699, 10, 'Gentle purifying clay mask.'], [4, 'Shea Body Butter', 799, 0, 'Deep moisture for dry skin.'], [4, 'Lip Care Duo', 499, 15, 'Tinted balm and overnight lip mask.'],
      [5, 'Leather Crossbody Bag', 3799, 30, 'Full-grain leather in tan.'], [5, 'Gold Hoop Earrings', 999, 20, 'Lightweight 18k gold-plated hoops.'], [5, 'Silk Printed Scarf', 1299, 10, 'Hand-rolled edges, earthy print.'], [5, 'Minimal Leather Wallet', 1499, 15, 'Slim wallet with RFID protection.'],
      [6, 'Cork Yoga Mat', 1899, 20, 'Non-slip eco-friendly yoga mat.'], [6, 'Insulated Steel Bottle', 899, 0, 'Keeps drinks cold 24h, hot 12h.'], [6, 'Linen Journal Set', 649, 10, 'Two dotted journals with a pen.'], [6, 'Ceramic Coffee Pour-Over', 1399, 18, 'Brew café coffee at home.']];
    let n = 0; for (const [c, name, price, d, desc] of prods) { n++; await q('INSERT INTO products(name,description,price,discount_percent,stock,sold,rating,image,category_id) VALUES(?,?,?,?,?,?,?,?,?)', [name, desc, price, d, name === 'Soy Wax Candle Trio' || name === 'Shea Body Butter' || name === 'Insulated Steel Bottle' ? 0 : 5 + (n * 7) % 40, (n * 13) % 60, (38 + (n * 3) % 13) / 10, 'https://picsum.photos/seed/cartify' + n + '/600/600', c]); }
  }
}
// ---------- FRONTEND ----------
const HTML = String.raw`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CARTIFY – Shopping Made Simple</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22><text y=%2220%22 font-size=%2220%22>🛍️</text></svg>">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Playfair+Display:wght@500;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root{--cream:#F8F3EB;--ivory:#FFFDF9;--beige:#E9DDCD;--sand:#D8C2AA;--terra:#C9795D;--orange:#D98255;--cocoa:#725343;--esp:#342820;--sage:#A6B49A;--rose:#E87991;--coral:#F08072;--r:16px;--sh:0 6px 20px rgba(52,40,32,.08)}
*{box-sizing:border-box;margin:0}body{font-family:'DM Sans',sans-serif;background:var(--cream);color:var(--esp);overflow-x:hidden}
h1,h2,h3,.logo{font-family:'Playfair Display',serif}a{color:inherit;text-decoration:none}img{max-width:100%;display:block}
.wrap{max-width:1200px;margin:auto;padding:0 20px}.btn{border:0;background:var(--terra);color:#fff;padding:12px 24px;border-radius:99px;cursor:pointer;font:500 15px 'DM Sans';transition:.2s;display:inline-block}.btn:hover{background:var(--orange);transform:translateY(-2px)}
.btn.o{background:transparent;color:var(--cocoa);border:1.5px solid var(--cocoa)}.btn.s{padding:8px 16px;font-size:13px}.btn.d{background:var(--esp)}
nav{position:sticky;top:0;z-index:50;background:rgba(255,253,249,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--beige)}nav .wrap{display:flex;align-items:center;gap:22px;height:68px}
.logo{font-size:26px;font-weight:700;color:var(--terra);letter-spacing:1px}.links{display:flex;gap:20px;flex:1}.links a{color:var(--cocoa);font-weight:500}.links a:hover{color:var(--terra)}
.nr{display:flex;gap:14px;align-items:center}.ib{position:relative;font-size:21px;cursor:pointer;background:none;border:0}.cnt{position:absolute;top:-6px;right:-9px;background:var(--rose);color:#fff;font-size:11px;border-radius:99px;padding:1px 6px}
.sb{padding:9px 14px;border:1px solid var(--sand);border-radius:99px;background:var(--cream);width:170px;font:inherit}.burger{display:none}
.hero{display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:center;padding:60px 0}.hero h1{font-size:clamp(36px,5vw,60px);line-height:1.1;margin-bottom:16px}.hero p{color:var(--cocoa);margin-bottom:26px;font-size:18px}.hero img{border-radius:200px 200px var(--r) var(--r);height:480px;width:100%;object-fit:cover;box-shadow:var(--sh)}
.sec{padding:36px 0}.sec h2{font-size:32px;margin-bottom:6px}.sec .sub{color:var(--cocoa);margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:22px}.cats{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:16px}
.cat{position:relative;border-radius:var(--r);overflow:hidden;height:170px;cursor:pointer}.cat img{width:100%;height:100%;object-fit:cover;transition:.4s}.cat:hover img{transform:scale(1.07)}.cat span{position:absolute;inset:auto 0 0;padding:14px;color:#fff;font:600 18px 'Playfair Display';background:linear-gradient(transparent,rgba(52,40,32,.75))}
.card{background:var(--ivory);border-radius:var(--r);overflow:hidden;box-shadow:var(--sh);transition:.25s}.card:hover{transform:translateY(-4px)}.im{position:relative;aspect-ratio:1;overflow:hidden;cursor:pointer;user-select:none}.im img{width:100%;height:100%;object-fit:cover}
.badge{position:absolute;left:10px;top:10px;background:var(--terra);color:#fff;font-size:12px;padding:3px 10px;border-radius:99px}.oos{background:var(--esp)}
.heart{position:absolute;right:10px;top:10px;width:40px;height:40px;border-radius:50%;border:0;background:rgba(255,253,249,.92);cursor:pointer;display:grid;place-items:center;z-index:2}
.heart svg{width:22px;height:22px;fill:none;stroke:var(--cocoa);stroke-width:2;transition:.2s}.heart.on svg{fill:var(--rose);stroke:var(--rose)}.heart.pop svg{animation:pop .5s}
@keyframes pop{0%{transform:scale(1)}30%{transform:scale(1.5)}60%{transform:scale(.9)}100%{transform:scale(1)}}
.sp{position:absolute;width:6px;height:6px;border-radius:50%;pointer-events:none;animation:spark .6s forwards}@keyframes spark{to{transform:translate(var(--x),var(--y)) scale(0);opacity:0}}
.big{position:absolute;inset:0;display:grid;place-items:center;pointer-events:none;z-index:3}.big svg{width:110px;fill:var(--rose);filter:drop-shadow(0 4px 12px rgba(0,0,0,.25));animation:bigp .9s forwards}@keyframes bigp{0%{transform:scale(0);opacity:0}25%{transform:scale(1.2);opacity:1}50%{transform:scale(.95)}80%{transform:scale(1);opacity:1}100%{transform:scale(1.1);opacity:0}}
.ci{padding:14px}.ci small{color:var(--cocoa)}.ci h3{font:600 16px 'DM Sans';margin:4px 0}.pr{display:flex;gap:8px;align-items:baseline;margin:6px 0 10px}.pr b{font-size:18px;color:var(--terra)}.pr s{color:#999;font-size:13px}.pr i{color:var(--sage);font-size:13px;font-style:normal;font-weight:700}
.row{display:flex;gap:8px;flex-wrap:wrap}.star{color:#E0A030;font-size:13px}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}.bar input,.bar select,.f input,.f select,.f textarea{padding:10px 14px;border:1px solid var(--sand);border-radius:12px;background:var(--ivory);font:inherit}
.box{background:var(--ivory);border-radius:var(--r);padding:24px;box-shadow:var(--sh)}.f{display:grid;gap:12px}.f label{font-size:13px;color:var(--cocoa);font-weight:500}.f input,.f select,.f textarea{width:100%}.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.auth{max-width:440px;margin:50px auto}.err{color:#b33;font-size:14px;min-height:18px}
.ln{display:flex;gap:14px;align-items:center;padding:14px 0;border-bottom:1px solid var(--beige)}.ln img{width:72px;height:72px;object-fit:cover;border-radius:12px}.ln .g{flex:1}.q{display:flex;align-items:center;gap:8px}.q button{width:28px;height:28px;border-radius:50%;border:1px solid var(--sand);background:var(--ivory);cursor:pointer}
.lay{display:grid;grid-template-columns:2fr 1fr;gap:24px}.det{display:grid;grid-template-columns:1fr 1fr;gap:40px}.det .im{border-radius:var(--r);cursor:default}
.empty{text-align:center;padding:70px 20px;color:var(--cocoa)}.empty .e{font-size:60px}
.tl{display:flex;margin:16px 0}.tl div{flex:1;text-align:center;font-size:12px;color:#999;position:relative}.tl div:before{content:'';display:block;width:16px;height:16px;border-radius:50%;background:var(--beige);margin:0 auto 6px;position:relative;z-index:1}.tl div:after{content:'';position:absolute;top:7px;left:-50%;width:100%;height:2px;background:var(--beige)}.tl div:first-child:after{display:none}.tl .dn{color:var(--esp)}.tl .dn:before,.tl .dn:after{background:var(--sage)}
.pill{padding:3px 12px;border-radius:99px;font-size:12px;background:var(--beige)}.Delivered{background:var(--sage);color:#fff}.Cancelled{background:var(--coral);color:#fff}.Pending{background:#f3d9a6}
.promo{background:var(--cocoa);color:var(--cream);border-radius:var(--r);padding:44px;display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}.promo h2{margin:0}
.tst{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:18px}.tst .box p{font-style:italic;margin-bottom:10px}
footer{background:var(--esp);color:var(--sand);margin-top:50px;padding:40px 0}footer .wrap{display:grid;grid-template-columns:2fr 1fr 1fr;gap:30px}footer a{display:block;margin:6px 0}
#toast{position:fixed;bottom:26px;left:50%;transform:translate(-50%,100px);background:var(--esp);color:#fff;padding:12px 24px;border-radius:99px;transition:.35s;z-index:99;box-shadow:var(--sh)}#toast.show{transform:translate(-50%,0)}
.adm{display:grid;grid-template-columns:200px 1fr;gap:24px;padding:30px 0}.side{background:var(--esp);border-radius:var(--r);padding:16px;height:fit-content}.side a{display:block;color:var(--sand);padding:10px 12px;border-radius:10px;cursor:pointer}.side a.on,.side a:hover{background:var(--cocoa);color:#fff}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px}.stat b{display:block;font:700 26px 'Playfair Display';color:var(--terra)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--beige)}.tw{overflow-x:auto}.low{color:var(--coral);font-weight:700}
@media(max-width:800px){.links{display:none;position:absolute;top:68px;left:0;right:0;background:var(--ivory);flex-direction:column;padding:16px 20px}.links.open{display:flex}.burger{display:block}.sb{width:100px}.hero,.lay,.det,.adm,footer .wrap,.two{grid-template-columns:1fr}.hero img{height:300px}.side{display:flex;overflow-x:auto}.grid{grid-template-columns:repeat(2,1fr);gap:12px}}
</style></head><body><nav><div class="wrap"><a href="#/" class="logo">🛍 CARTIFY</a><div class="links" id="links"><a href="#/">Home</a><a href="#/shop">Shop</a><a href="#/shop?categories=1">Categories</a><a href="#/about">About</a><a href="#/contact">Contact</a></div><div class="nr" id="nr"></div><button class="ib burger" onclick="document.getElementById('links').classList.toggle('open')">☰</button></div></nav>
<main id="app" class="wrap"></main><footer><div class="wrap"><div><div class="logo" style="color:var(--sand)">CARTIFY</div><p>Shopping Made Simple.</p></div><div><a href="#/shop">Shop</a><a href="#/wishlist">Wishlist</a><a href="#/orders">My Orders</a></div><div><a href="#/about">About</a><a href="#/contact">Contact</a></div></div></footer><div id="toast"></div>
<script>
var U=null,WL=new Set(),CC=0,CATS=[],H='<svg viewBox="0 0 24 24"><path d="M12 21s-7-4.6-9.5-9C.7 8.600 2.600 4.500 6.500 4.500c2 0 3.700 1.100 5.500 3 1.800-1.900 3.500-3 5.500-3 3.900 0 5.800 4.100 4 7.500C19 16.400 12 21 12 21z"/></svg>';
var $=function(s){return document.querySelector(s)},app=$('#app'),money=function(n){return '₹'+Number(n).toLocaleString('en-IN')};
async function api(p,m,b){var r=await fetch('/api'+p,{method:m||'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});var d=await r.json().catch(function(){return{}});if(!r.ok)throw new Error(d.error||'Error');return d}
function toast(m){var t=$('#toast');t.textContent=m;t.className='show';clearTimeout(t.t);t.t=setTimeout(function(){t.className=''},2200)}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
async function refresh(){if(U){try{WL=new Set((await api('/wishlist')).map(function(x){return x.id}));CC=(await api('/cart')).items.reduce(function(a,i){return a+i.quantity},0)}catch(e){}}else{WL=new Set();CC=0}nav()}
function nav(){$('#nr').innerHTML='<input class="sb" placeholder="Search…" onkeydown="if(event.key===\'Enter\')location.hash=\'#/shop?search=\'+encodeURIComponent(this.value)"><button class="ib" onclick="location.hash=\'#/wishlist\'">♡<span class="cnt">'+WL.size+'</span></button><button class="ib" onclick="location.hash=\'#/cart\'">🛒<span class="cnt">'+CC+'</span></button>'+(U?'<span style="font-size:14px">Hi, '+esc(U.name.split(' ')[0])+'</span><a class="btn s o" href="#/orders">Orders</a>'+(U.role==='admin'?'<a class="btn s" href="#/admin">Admin</a>':'')+'<button class="btn s d" onclick="logout()">Logout</button>':'<a class="btn s o" href="#/login">Login</a><a class="btn s" href="#/register">Register</a>')}
async function logout(){await api('/auth/logout','POST');U=null;await refresh();location.hash='#/';toast('Logged out')}
function stars(r){return '<span class="star">'+'★'.repeat(Math.round(r))+'☆'.repeat(5-Math.round(r))+' '+r+'</span>'}
function card(p){var on=WL.has(p.id);return '<div class="card"><div class="im" ondblclick="dbl('+p.id+',this)"><img loading="lazy" src="'+esc(p.image)+'" alt="'+esc(p.name)+'" onclick="location.hash=\'#/product/'+p.id+'\'">'+(p.discount_percent?'<span class="badge">-'+p.discount_percent+'%</span>':'')+(p.stock<1?'<span class="badge oos" style="top:46px">Out of stock</span>':'')+'<button class="heart'+(on?' on':'')+'" data-h="'+p.id+'" onclick="like('+p.id+',event)">'+H+'</button></div><div class="ci"><small>'+esc(p.category)+'</small><h3>'+esc(p.name)+'</h3>'+stars(p.rating)+'<div class="pr"><b>'+money(p.sale_price)+'</b>'+(p.discount_percent?'<s>'+money(p.price)+'</s><i>'+p.discount_percent+'% off</i>':'')+'</div><div class="row"><button class="btn s" '+(p.stock<1?'disabled style="opacity:.5"':'')+' onclick="addCart('+p.id+')">Add to Cart</button><a class="btn s o" href="#/product/'+p.id+'">Quick View</a></div></div></div>'}
function spark(b){for(var i=0;i<8;i++){var s=document.createElement('i');s.className='sp';var a=i*45*Math.PI/180;s.style.cssText='left:17px;top:17px;--x:'+Math.cos(a)*26+'px;--y:'+Math.sin(a)*26+'px;background:'+['#E87991','#F08072','#D98255','#A6B49A'][i%4];b.appendChild(s);setTimeout(function(){s.remove()},600)}}
async function like(id,ev,force){if(ev)ev.stopPropagation();if(!U){toast('Please login to use your wishlist');location.hash='#/login';return}
 var on=!WL.has(id);on?WL.add(id):WL.delete(id);document.querySelectorAll('[data-h="'+id+'"]').forEach(function(b){b.classList.toggle('on',on);if(on){b.classList.remove('pop');void b.offsetWidth;b.classList.add('pop');spark(b)}});nav();
 try{if(on)await api('/wishlist','POST',{productId:id});else await api('/wishlist/'+id,'DELETE');toast(on?'Added to your wishlist!':'Removed from your wishlist.');if(!on&&location.hash.indexOf('wishlist')>0)route()}catch(e){on?WL.delete(id):WL.add(id);document.querySelectorAll('[data-h="'+id+'"]').forEach(function(b){b.classList.toggle('on',!on)});nav();toast(e.message)}}
function dbl(id,el){var d=document.createElement('div');d.className='big';d.innerHTML=H;el.appendChild(d);setTimeout(function(){d.remove()},900);if(!U||!WL.has(id))like(id);}
async function addCart(id,qty){if(!U){toast('Please login to add to cart');location.hash='#/login';return}try{var c=await api('/cart','POST',{productId:id,quantity:qty||1});CC=c.items.reduce(function(a,i){return a+i.quantity},0);nav();toast('Added to cart 🛒')}catch(e){toast(e.message)}}
function route(){scrollTo(0,0);document.getElementById('links').classList.remove('open');var h=location.hash.slice(1)||'/',pq=h.split('?'),path=pq[0],qs=new URLSearchParams(pq[1]||'');var m;
 if(path==='/')return home();if(path==='/shop')return shop(qs);if(m=path.match(/^\/product\/(\d+)/))return product(m[1]);if(path==='/login'||path==='/register')return authPage(path==='/login');
 if(path==='/wishlist')return wish();if(path==='/cart')return cart();if(path==='/checkout')return checkout();if(m=path.match(/^\/success\/(\d+)/))return success(m[1]);if(path==='/orders')return orders();if(path==='/admin')return adminPage(qs.get('t')||'dash');
 if(path==='/about')return app.innerHTML='<div class="sec"><h2>About CARTIFY</h2><p class="sub">Shopping Made Simple.</p><div class="box"><p>CARTIFY brings together fashion, electronics, home, beauty and lifestyle products in one warm, easy-to-use store. Every item is carefully selected so everyday shopping feels simple and delightful.</p></div></div>';
 if(path==='/contact')return app.innerHTML='<div class="sec"><h2>Contact</h2><div class="box f" style="max-width:520px"><label>Email</label><p>support@cartify.com</p><label>Phone</label><p>+91 00000 00000</p></div></div>';app.innerHTML='<div class="empty"><div class="e">🧭</div><h2>Page not found</h2></div>'}
async function home(){app.innerHTML='<div class="empty">Loading…</div>';CATS=await api('/categories');var secs=[['Featured Products','featured','Handpicked favourites','popular'],['New Arrivals','new','Fresh in this week','new'],['Trending Products','trend','What everyone is loving','rating'],['Best Sellers','best','Most loved by customers','popular'],['Special Offers','offer','Biggest savings right now','discount']];var out='<section class="hero"><div><h1>Find Your Everyday Favorites.</h1><p>Discover products you\'ll love, carefully selected to make everyday shopping simple and delightful.</p><div class="row"><a class="btn" href="#/shop">Explore Collection</a><a class="btn o" href="#/shop">Shop Now</a></div></div><img src="https://picsum.photos/seed/cartifyhero/700/800" alt="Lifestyle"></section><section class="sec"><h2>Shop by Category</h2><div class="cats">'+CATS.map(function(c){return '<div class="cat" onclick="location.hash=\'#/shop?category='+c.id+'\'"><img src="'+esc(c.image)+'"><span>'+esc(c.name)+'</span></div>'}).join('')+'</div></section>';
 var res=await Promise.all(secs.map(function(s){return api('/products?limit=4&sort='+s[3])}));secs.forEach(function(s,i){out+='<section class="sec"><h2>'+s[0]+'</h2><p class="sub">'+s[2]+'</p><div class="grid">'+res[i].items.map(card).join('')+'</div></section>';if(i===1)out+='<div class="promo"><div><h2>Up to 25% off lifestyle picks</h2><p>Cosy up your home this season.</p></div><a class="btn" href="#/shop?sort=discount">Shop offers</a></div>'});
 out+='<section class="sec"><h2>Loved by customers</h2><br><div class="tst"><div class="box"><p>“Gorgeous quality and super fast delivery.”</p><b>— Ananya R.</b></div><div class="box"><p>“The wishlist heart is so satisfying!”</p><b>— Rahul M.</b></div><div class="box"><p>“My go-to for home decor.”</p><b>— Priya S.</b></div></div></section><section class="sec"><div class="promo"><div><h2>Join the CARTIFY letter</h2><p>Offers and new arrivals, straight to your inbox.</p></div><div class="row"><input id="nl" class="sb" style="width:220px" placeholder="you@email.com"><button class="btn" onclick="sub()">Subscribe</button></div></div></section>';app.innerHTML=out}
async function sub(){try{await api('/newsletter/subscribe','POST',{email:$('#nl').value});toast('Subscribed. Thank you!')}catch(e){toast(e.message)}}
var PG=1;async function shop(qs){CATS=await api('/categories');var f={search:qs.get('search')||'',category:qs.get('category')||'',sort:qs.get('sort')||'',min:qs.get('min')||'',max:qs.get('max')||''};
 app.innerHTML='<div class="sec"><h2>Shop</h2><div class="bar"><input id="fs" placeholder="Search products" value="'+esc(f.search)+'"><select id="fc"><option value="">All categories</option>'+CATS.map(function(c){return '<option value="'+c.id+'"'+(f.category==c.id?' selected':'')+'>'+esc(c.name)+'</option>'}).join('')+'</select><input id="fmin" type="number" placeholder="Min ₹" style="width:100px" value="'+f.min+'"><input id="fmax" type="number" placeholder="Max ₹" style="width:100px" value="'+f.max+'"><select id="fo"><option value="">Default</option><option value="new">Newest</option><option value="popular">Popularity</option><option value="price_asc">Price: Low to High</option><option value="price_desc">Price: High to Low</option><option value="discount">Biggest discount</option></select><button class="btn s" onclick="shopGo()">Apply</button></div><div id="res"></div></div>';$('#fo').value=f.sort;PG=1;load(false)}
function shopGo(){var p=new URLSearchParams({search:$('#fs').value,category:$('#fc').value,min:$('#fmin').value,max:$('#fmax').value,sort:$('#fo').value});for(var k of Array.from(p.keys()))if(!p.get(k))p.delete(k);location.hash='#/shop?'+p}
async function load(more){var p=new URLSearchParams({search:$('#fs').value,category:$('#fc').value,min:$('#fmin').value,max:$('#fmax').value,sort:$('#fo').value,page:PG,limit:12});var d=await api('/products?'+p);var r=$('#res');if(!more)r.innerHTML='<div class="grid" id="pg"></div>';if(!d.items.length&&!more){r.innerHTML='<div class="empty"><div class="e">🔍</div><h3>No products found</h3><p>Try different filters.</p></div>';return}$('#pg').insertAdjacentHTML('beforeend',d.items.map(card).join(''));var old=$('#lm');if(old)old.remove();if(PG<d.pages)r.insertAdjacentHTML('beforeend','<p style="text-align:center;margin-top:24px" id="lm"><button class="btn o" onclick="PG++;load(true)">Load more</button></p>')}
async function product(id){try{var p=await api('/products/'+id)}catch(e){return app.innerHTML='<div class="empty"><div class="e">😕</div><h2>Product not found</h2></div>'}
 app.innerHTML='<div class="sec"><div class="det"><div class="im" ondblclick="dbl('+p.id+',this)"><img src="'+esc(p.image)+'"><button class="heart'+(WL.has(p.id)?' on':'')+'" data-h="'+p.id+'" onclick="like('+p.id+',event)">'+H+'</button></div><div><small>'+esc(p.category)+'</small><h2>'+esc(p.name)+'</h2>'+stars(p.rating)+'<div class="pr"><b style="font-size:28px">'+money(p.sale_price)+'</b>'+(p.discount_percent?'<s>'+money(p.price)+'</s><i>'+p.discount_percent+'% off</i>':'')+'</div><p style="margin:14px 0">'+esc(p.description)+'</p><p>'+(p.stock>0?'<span style="color:#5a7a4a">● In stock ('+p.stock+' left)</span>':'<span class="low">● Out of stock</span>')+'</p><br><div class="q"><button onclick="qty(-1)">−</button><b id="qv">1</b><button onclick="qty(1,'+p.stock+')">+</button></div><br><div class="row"><button class="btn" '+(p.stock<1?'disabled style="opacity:.5"':'')+' onclick="addCart('+p.id+',+$(\'#qv\').textContent)">Add to Cart</button><button class="btn o" onclick="like('+p.id+')">♡ Wishlist</button></div><div class="box" style="margin-top:20px"><b>🚚 Delivery</b><p>Free above ₹999, otherwise ₹49. Delivered in 3–6 days. Cash on Delivery available.</p></div></div></div><h2 style="margin:40px 0 16px">Related products</h2><div class="grid">'+p.related.map(card).join('')+'</div></div>'}
function qty(d,m){var e=$('#qv'),n=+e.textContent+d;if(n>=1&&(!m||n<=m))e.textContent=n}
function authPage(isLogin){if(U){location.hash='#/';return}app.innerHTML='<div class="auth box f"><h2>'+(isLogin?'Welcome back':'Create account')+'</h2>'+(isLogin?'':'<div><label>Full name</label><input id="an"></div><div><label>Phone</label><input id="ap"></div>')+'<div><label>Email</label><input id="ae" type="email"></div><div><label>Password</label><input id="apw" type="password"></div>'+(isLogin?'':'<div><label>Confirm password</label><input id="ac" type="password"></div>')+'<label><input type="checkbox" onchange="$(\'#apw\').type=this.checked?\'text\':\'password\'"> Show password</label><div class="err" id="er"></div><button class="btn" onclick="doAuth('+isLogin+')">'+(isLogin?'Login':'Register')+'</button><p>'+(isLogin?'New here? <a href="#/register" style="color:var(--terra)">Create an account</a>':'Have an account? <a href="#/login" style="color:var(--terra)">Login</a>')+'</p></div>'}
async function doAuth(isLogin){try{var b={email:$('#ae').value,password:$('#apw').value};if(!isLogin){if(b.password!==$('#ac').value)throw new Error('Passwords do not match');b.name=$('#an').value;b.phone=$('#ap').value}U=(await api('/auth/'+(isLogin?'login':'register'),'POST',b)).user;await refresh();toast('Welcome, '+U.name+'!');location.hash=U.role==='admin'?'#/admin':'#/'}catch(e){$('#er').textContent=e.message}}
async function wish(){if(!U){location.hash='#/login';return}var l=await api('/wishlist');app.innerHTML='<div class="sec"><h2>My Wishlist</h2>'+(l.length?'<div class="grid">'+l.map(card).join('')+'</div>':'<div class="empty"><div class="e" style="color:var(--rose)">♡</div><h3>Your wishlist is empty</h3><p>Tap the heart on products you love.</p><br><a class="btn" href="#/shop">Discover products</a></div>')+'</div>'}
async function cart(){if(!U){location.hash='#/login';return}var c=await api('/cart');if(!c.items.length)return app.innerHTML='<div class="empty"><div class="e">🛒</div><h3>Your cart is empty</h3><br><a class="btn" href="#/shop">Start shopping</a></div>';
 app.innerHTML='<div class="sec"><h2>Shopping Cart</h2><br><div class="lay"><div class="box">'+c.items.map(function(i){return '<div class="ln"><img src="'+esc(i.image)+'"><div class="g"><b>'+esc(i.name)+'</b><br>'+money(i.sale_price)+'</div><div class="q"><button onclick="cq('+i.item_id+','+(i.quantity-1)+')">−</button><b>'+i.quantity+'</b><button onclick="cq('+i.item_id+','+(i.quantity+1)+')">+</button></div><b>'+money(i.sale_price*i.quantity)+'</b><button class="ib" onclick="cdel('+i.item_id+')">🗑</button></div>'}).join('')+'</div>'+sum(c)+'</div></div>'}
function sum(c,btn){return '<div class="box" style="height:fit-content"><h3>Order Summary</h3><p class="ln">Subtotal<span class="g" style="text-align:right">'+money(c.subtotal)+'</span></p><p class="ln">Shipping<span class="g" style="text-align:right">'+(c.shipping?money(c.shipping):'Free')+'</span></p><p class="ln"><b>Total</b><b class="g" style="text-align:right">'+money(c.total)+'</b></p><br>'+(btn===false?'':'<a class="btn" href="#/checkout">Checkout</a>')+'</div>'}
async function cq(id,n){if(n<1)return cdel(id);try{await api('/cart/'+id,'PUT',{quantity:n});await refresh();cart()}catch(e){toast(e.message)}}
async function cdel(id){await api('/cart/'+id,'DELETE');await refresh();cart()}
async function checkout(){if(!U){location.hash='#/login';return}var c=await api('/cart');if(!c.items.length){location.hash='#/cart';return}
 app.innerHTML='<div class="sec"><h2>Checkout</h2><br><div class="lay"><div class="box f"><div class="two"><div><label>Name</label><input id="cn" value="'+esc(U.name)+'"></div><div><label>Phone</label><input id="cp"></div></div><div><label>Email</label><input id="ce" value="'+esc(U.email)+'"></div><div><label>Delivery address</label><textarea id="ca" rows="2"></textarea></div><div class="two"><div><label>City</label><input id="cc"></div><div><label>State</label><input id="cs"></div></div><div><label>Postal code</label><input id="cz"></div><div class="pill" style="width:fit-content;padding:8px 14px">💵 Cash on Delivery</div><div class="err" id="er"></div><button class="btn" onclick="place()">Place Order</button></div><div>'+c.items.map(function(i){return '<div class="ln"><img src="'+esc(i.image)+'"><div class="g">'+esc(i.name)+'<br><small>Qty '+i.quantity+'</small></div>'+money(i.sale_price*i.quantity)+'</div>'}).join('')+sum(c,false)+'</div></div></div>'}
async function place(){try{var r=await api('/orders','POST',{name:$('#cn').value,phone:$('#cp').value,email:$('#ce').value,address:$('#ca').value,city:$('#cc').value,state:$('#cs').value,postal_code:$('#cz').value});await refresh();location.hash='#/success/'+r.orderId}catch(e){$('#er').textContent=e.message}}
function success(id){app.innerHTML='<div class="empty"><div class="e">🎉</div><h2>Order placed!</h2><p>Your order ID is <b>#CF'+(1000+ +id)+'</b>. Pay on delivery.</p><br><a class="btn" href="#/orders">Track order</a></div>'}
var STEPS=['Pending','Confirmed','Processing','Shipped','Delivered'];
function tl(s){if(s==='Cancelled')return '<span class="pill Cancelled">Cancelled</span>';var i=STEPS.indexOf(s);return '<div class="tl">'+STEPS.map(function(x,k){return '<div class="'+(k<=i?'dn':'')+'">'+x+'</div>'}).join('')+'</div>'}
async function orders(){if(!U){location.hash='#/login';return}var o=await api('/orders');app.innerHTML='<div class="sec"><h2>My Orders</h2><br>'+(o.length?o.map(function(x){return '<div class="box" style="margin-bottom:16px"><div class="row" style="justify-content:space-between"><b>#CF'+(1000+x.id)+'</b><span>'+new Date(x.created_at).toLocaleDateString()+'</span><span class="pill '+x.status+'">'+x.status+'</span><b>'+money(x.total)+'</b></div>'+tl(x.status)+x.items.map(function(i){return '<div class="ln"><img src="'+esc(i.image)+'"><div class="g">'+esc(i.name)+' × '+i.quantity+'</div>'+money(i.price*i.quantity)+'</div>'}).join('')+'</div>'}).join(''):'<div class="empty"><div class="e">📦</div><h3>No orders yet</h3></div>')+'</div>'}
// ---- admin ----
var TABS=[['dash','Dashboard'],['products','Products'],['categories','Categories'],['orders','Orders'],['customers','Customers'],['inventory','Inventory']],ch;
async function adminPage(t){if(!U||U.role!=='admin'){app.innerHTML='<div class="empty"><div class="e">🔒</div><h2>Admin access only</h2></div>';return}
 app.innerHTML='<div class="adm"><div class="side">'+TABS.map(function(x){return '<a class="'+(x[0]===t?'on':'')+'" onclick="location.hash=\'#/admin?t='+x[0]+'\'">'+x[1]+'</a>'}).join('')+'<a onclick="logout()">Logout</a></div><div id="ad"></div></div>';var d=$('#ad');
 if(t==='dash'){var s=await api('/admin/dashboard');d.innerHTML='<div class="stats">'+[['Products',s.products],['Customers',s.customers],['Orders',s.orders],['Revenue',money(s.revenue)],['Pending',s.pending],['Low stock',s.lowStock]].map(function(x){return '<div class="box stat"><small>'+x[0]+'</small><b>'+x[1]+'</b></div>'}).join('')+'</div><div class="box"><h3>Sales (last 7 days)</h3><canvas id="chart" height="110"></canvas></div><br><div class="two"><div class="box tw"><h3>Recent orders</h3><table>'+s.recentOrders.map(function(o){return '<tr><td>#CF'+(1000+o.id)+'</td><td>'+esc(o.name)+'</td><td>'+money(o.total)+'</td><td>'+o.status+'</td></tr>'}).join('')+'</table></div><div class="box tw"><h3>Top sellers</h3><table>'+s.top.map(function(o){return '<tr><td>'+esc(o.name)+'</td><td>'+o.sold+' sold</td></tr>'}).join('')+'</table><h3 style="margin-top:14px">Recent customers</h3><table>'+s.recentCustomers.map(function(o){return '<tr><td>'+esc(o.name)+'</td><td>'+esc(o.email)+'</td></tr>'}).join('')+'</table></div></div>';
  if(ch)ch.destroy();ch=new Chart($('#chart'),{type:'line',data:{labels:s.sales.map(function(x){return x.d}),datasets:[{label:'Revenue ₹',data:s.sales.map(function(x){return x.t}),borderColor:'#C9795D',backgroundColor:'rgba(201,121,93,.15)',fill:true,tension:.3}]}})}
 if(t==='products'){var ps=await api('/products?limit=50'),cs=await api('/categories');d.innerHTML='<div class="box f"><h3 id="ft">Add product</h3><input type="hidden" id="pid"><div class="two"><input id="pn" placeholder="Name"><select id="pc">'+cs.map(function(c){return '<option value="'+c.id+'">'+esc(c.name)+'</option>'}).join('')+'</select></div><div class="two"><input id="pp" type="number" placeholder="Price ₹"><input id="pd" type="number" placeholder="Discount %" value="0"></div><div class="two"><input id="ps" type="number" placeholder="Stock"><input id="pi" placeholder="Image URL"></div><textarea id="pde" placeholder="Description"></textarea><div class="err" id="er"></div><button class="btn" onclick="saveP()">Save product</button></div><br><div class="box tw"><table><tr><th>Name</th><th>Category</th><th>Price</th><th>Disc</th><th>Stock</th><th></th></tr>'+ps.items.map(function(p){return '<tr><td>'+esc(p.name)+'</td><td>'+esc(p.category)+'</td><td>'+money(p.price)+'</td><td>'+p.discount_percent+'%</td><td>'+p.stock+'</td><td><button class="btn s o" onclick=\'editP('+JSON.stringify(p).replace(/\\'/g,"&#39;")+')\'>Edit</button> <button class="btn s d" onclick="delP('+p.id+')">Delete</button></td></tr>'}).join('')+'</table></div>'}
 if(t==='categories'){var cs2=await api('/categories');d.innerHTML='<div class="box f"><div class="two"><input id="cn2" placeholder="Category name"><input id="ci2" placeholder="Image URL"></div><div class="err" id="er"></div><button class="btn" onclick="addCat()">Add category</button></div><br><div class="box tw"><table>'+cs2.map(function(c){return '<tr><td>'+esc(c.name)+'</td><td>'+c.products+' products</td><td><button class="btn s o" onclick="renCat('+c.id+',\''+esc(c.name).replace(/\'/g,'')+'\')">Rename</button> <button class="btn s d" onclick="delCat('+c.id+')">Delete</button></td></tr>'}).join('')+'</table></div>'}
 if(t==='orders'){var os=await api('/admin/orders');d.innerHTML='<div class="box tw"><table><tr><th>ID</th><th>Customer</th><th>Items</th><th>Total</th><th>Status</th></tr>'+os.map(function(o){return '<tr><td>#CF'+(1000+o.id)+'</td><td>'+esc(o.name)+'<br><small>'+esc(o.email)+' · '+esc(o.phone)+'<br>'+esc(o.address)+', '+esc(o.city)+', '+esc(o.state)+' '+esc(o.postal_code)+'</small></td><td>'+o.items.map(function(i){return esc(i.name)+' ×'+i.quantity}).join('<br>')+'</td><td>'+money(o.total)+'</td><td><select onchange="setSt('+o.id+',this.value)">'+['Pending','Confirmed','Processing','Shipped','Delivered','Cancelled'].map(function(s){return '<option'+(s===o.status?' selected':'')+'>'+s+'</option>'}).join('')+'</select></td></tr>'}).join('')+'</table></div>'}
 if(t==='customers'){d.innerHTML='<div class="bar"><input id="cs3" placeholder="Search customers" onkeyup="if(event.key===\'Enter\')custList()"><button class="btn s" onclick="custList()">Search</button></div><div id="cl"></div>';custList()}
 if(t==='inventory'){var iv=await api('/admin/inventory');d.innerHTML='<div class="box tw"><table><tr><th>Product</th><th>Category</th><th>Stock</th><th>Update</th></tr>'+iv.map(function(p){return '<tr><td>'+esc(p.name)+'</td><td>'+esc(p.category)+'</td><td class="'+(p.stock<10?'low':'')+'">'+p.stock+(p.stock===0?' (Out of stock)':p.stock<10?' (Low)':'')+'</td><td><input type="number" id="st'+p.id+'" value="'+p.stock+'" style="width:80px;padding:6px"> <button class="btn s" onclick="setStock('+p.id+')">Save</button></td></tr>'}).join('')+'</table></div>'}}
async function custList(){var u=await api('/admin/users?search='+encodeURIComponent($('#cs3').value||''));$('#cl').innerHTML='<div class="box tw"><table><tr><th>Name</th><th>Email</th><th>Phone</th><th>Orders</th><th>Status</th><th></th></tr>'+u.map(function(c){return '<tr><td>'+esc(c.name)+'</td><td>'+esc(c.email)+'</td><td>'+esc(c.phone)+'</td><td>'+c.orders+'</td><td>'+(c.is_active?'Active':'Disabled')+'</td><td><button class="btn s o" onclick="toggleU('+c.id+')">'+(c.is_active?'Disable':'Enable')+'</button></td></tr>'}).join('')+'</table></div>'}
async function toggleU(id){await api('/admin/users/'+id+'/toggle','PUT');custList()}
async function saveP(){var id=$('#pid').value,b={name:$('#pn').value,category_id:$('#pc').value,price:$('#pp').value,discount_percent:$('#pd').value||0,stock:$('#ps').value,image:$('#pi').value,description:$('#pde').value};try{await api(id?'/products/'+id:'/products',id?'PUT':'POST',b);toast('Product saved');adminPage('products')}catch(e){$('#er').textContent=e.message}}
function editP(p){$('#ft').textContent='Edit product';$('#pid').value=p.id;$('#pn').value=p.name;$('#pc').value=p.category_id;$('#pp').value=p.price;$('#pd').value=p.discount_percent;$('#ps').value=p.stock;$('#pi').value=p.image;$('#pde').value=p.description;scrollTo(0,0)}
async function delP(id){if(confirm('Delete this product?')){await api('/products/'+id,'DELETE');adminPage('products')}}
async function addCat(){try{await api('/categories','POST',{name:$('#cn2').value,image:$('#ci2').value});adminPage('categories')}catch(e){$('#er').textContent=e.message}}
async function renCat(id,n){var v=prompt('New name',n);if(v){await api('/categories/'+id,'PUT',{name:v});adminPage('categories')}}
async function delCat(id){try{await api('/categories/'+id,'DELETE');adminPage('categories')}catch(e){toast(e.message)}}
async function setSt(id,s){try{await api('/admin/orders/'+id+'/status','PUT',{status:s});toast('Status updated')}catch(e){toast(e.message)}}
async function setStock(id){try{await api('/admin/inventory/'+id,'PUT',{stock:$('#st'+id).value});toast('Stock updated');adminPage('inventory')}catch(e){toast(e.message)}}
window.addEventListener('hashchange',route);(async function(){try{U=(await api('/auth/me')).user}catch(e){}await refresh();route()})();
</script></body></html>`;
app.get('/', (_, res) => res.type('html').send(HTML));
initDb().then(() => app.listen(PORT, () => console.log('CARTIFY running → http://localhost:' + PORT))).catch(e => { console.error('Startup failed (check MySQL + DB_USER/DB_PASSWORD):', e.message); process.exit(1); });
