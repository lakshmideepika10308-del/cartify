# CARTIFY - Shopping Made Simple
Full-stack e-commerce app: Node.js + Express + MySQL + vanilla HTML/CSS/JS (frontend is served from server.js).

## Run
1. Install Node.js 18+ and MySQL 8 (make sure MySQL is running).
2. Open `.env` and set `DB_PASSWORD` to your MySQL root password.
3. In this folder run:
   npm install
   npm start
4. Open http://localhost:3000

The database `cartify_db`, tables, 6 categories, 24 products and the admin user are created automatically on first start.

## Admin
Email: admin@cartify.com  Password: Admin@123  (change after first login). Admin panel: http://localhost:3000/#/admin

## Features
Register/login (bcrypt, sessions), shop with search/filter/sort, product details, animated heart wishlist (double-click image too),
cart, Cash-on-Delivery checkout (MySQL transaction), order history + tracking, admin dashboard (Chart.js), product/category/order/customer/inventory management.

## API
Auth: POST /api/auth/register|login|logout, GET /api/auth/me
Products: GET/POST /api/products, GET/PUT/DELETE /api/products/:id
Categories: GET/POST /api/categories, PUT/DELETE /api/categories/:id
Wishlist: GET/POST /api/wishlist, DELETE /api/wishlist/:productId
Cart: GET/POST /api/cart, PUT/DELETE /api/cart/:itemId
Orders: POST/GET /api/orders, GET /api/orders/:id
Admin: GET /api/admin/dashboard|users|orders|inventory, PUT /api/admin/orders/:id/status
Newsletter: POST /api/newsletter/subscribe

## Notes
Sessions are in memory (restart = logout). Product images are URLs (sample images need internet).
