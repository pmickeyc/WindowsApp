from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category', backref='products')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    """Ensure the current user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def create_tables():
    """Create database tables and seed sample data if needed."""
    db.create_all()
    if not Category.query.first():
        default = Category(name='General')
        db.session.add(default)
        db.session.add(Product(name='Sample Item', price=9.99, category=default))
        db.session.commit()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    category_id = request.args.get('category')
    categories = Category.query.all()
    if category_id:
        products = Product.query.filter_by(category_id=category_id).all()
    else:
        products = Product.query.all()
    return render_template('index.html', products=products, categories=categories, selected_category=category_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('signup.html')

def get_cart():
    """Retrieve the cart from the session."""
    return session.setdefault('cart', {})

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    cart = get_cart()
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session.modified = True
    flash('Item added to cart')
    return redirect(url_for('index'))

@app.route('/cart')
def cart_view():
    cart = get_cart()
    items = []
    total = 0
    for pid, qty in cart.items():
        product = Product.query.get(int(pid))
        if product:
            subtotal = product.price * qty
            items.append({'product': product, 'quantity': qty, 'subtotal': subtotal})
            total += subtotal
    return render_template('cart.html', items=items, total=total)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart = get_cart()
    if not cart:
        flash('Cart is empty')
        return redirect(url_for('cart_view'))
    order = Order(user_id=current_user.id)
    for pid, qty in cart.items():
        product = Product.query.get(int(pid))
        if product:
            order.items.append(OrderItem(product_id=product.id, quantity=qty, price=product.price))
    db.session.add(order)
    db.session.commit()
    session['cart'] = {}
    flash('Order placed successfully')
    return redirect(url_for('profile'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('profile.html', user=current_user, orders=orders)


@app.route('/admin')
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    product_count = Product.query.count()
    order_count = Order.query.count()
    revenue = db.session.query(db.func.sum(OrderItem.price * OrderItem.quantity)).scalar() or 0
    return render_template('admin/dashboard.html', user_count=user_count, product_count=product_count,
                           order_count=order_count, revenue=revenue)


@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST' and 'delete' in request.form:
        uid = int(request.form['delete'])
        if uid != current_user.id:
            User.query.filter_by(id=uid).delete()
            db.session.commit()
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/products', methods=['GET', 'POST'])
@admin_required
def manage_products():
    if request.method == 'POST':
        if 'delete' in request.form:
            Product.query.filter_by(id=int(request.form['delete'])).delete()
            db.session.commit()
        else:
            name = request.form['name']
            price = float(request.form['price'])
            cat_id = int(request.form['category']) if request.form.get('category') else None
            category = Category.query.get(cat_id) if cat_id else None
            db.session.add(Product(name=name, price=price, category=category))
            db.session.commit()
    products = Product.query.all()
    categories = Category.query.all()
    return render_template('admin/products.html', products=products, categories=categories)


@app.route('/admin/orders')
@admin_required
def manage_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin/orders.html', orders=orders)

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=True)
