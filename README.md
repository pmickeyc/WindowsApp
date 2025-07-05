# E-Commerce Flask App

This is a simple e-commerce web application using Flask. It supports user registration, login, product listing, shopping carts and order history. An admin interface allows management of users, products and orders.

## Features

- Browse products by category
- Add items to a shopping cart
- Checkout and create orders
- View past orders from the profile page

## Setup

1. Create a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database and run the app:
   ```bash
   python app.py
   ```

## Database schema changes

If you alter the models and the schema changes, the existing `db.sqlite3` file
may no longer be compatible. You can either run migrations or simply remove the
database file so a new one is created on the next run.

Example of recreating the database:

```bash
rm db.sqlite3
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

## Admin Login

An initial admin user is created automatically with username `admin` and password `admin`. Use this account to access the `/admin` area for managing data.
