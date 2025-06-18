from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime
import os

import pandas as pd

app = Flask(__name__)
app.secret_key = 'your_secret_key'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'medikaze.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Medicine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    price = db.Column(db.Float)
    stock = db.Column(db.Integer)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    med_name = db.Column(db.String(100))
    med_price = db.Column(db.Float)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))

# Initialize DB
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    medicines = Medicine.query.all()
    return render_template('index.html', medicines=medicines)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'admin' in request.form

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect('/signup')

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            is_admin=is_admin
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.')
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            session['is_admin'] = user.is_admin
            flash('Logged in successfully!')
            return redirect('/admin' if user.is_admin else '/')
        else:
            flash('Invalid credentials!')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect('/')


@app.route('/add-to-cart/<int:med_id>')
def add_to_cart(med_id):
    medicine = Medicine.query.get(med_id)
    if 'cart' not in session:
        session['cart'] = []
    session['cart'].append({'id': med_id, 'name': medicine.name, 'price': medicine.price})
    flash("Added to cart!")
    return redirect('/')

@app.route('/cart')
def cart():
    return render_template('cart.html', cart=session.get('cart', []))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        file = request.files['csv']
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
            for _, row in df.iterrows():
                new_med = Medicine(name=row['name'], price=row['price'], stock=row['stock'])
                db.session.add(new_med)
            db.session.commit()
            flash("Medicines uploaded!")
    medicines = Medicine.query.all()
    return render_template('admin.html', medicines=medicines)

@app.route('/admin/orders')
def admin_orders():
    if not session.get('is_admin'):
        flash("Unauthorized access.")
        return redirect('/')
    orders = Order.query.order_by(Order.timestamp.desc()).all()
    return render_template('admin_orders.html', orders=orders)


@app.route('/place-order', methods=['POST'])
def place_order():
    if 'user' not in session:
        flash("Please login to place order.")
        return redirect('/login')

    cart = session.get('cart', [])
    if not cart:
        flash("Cart is empty!")
        return redirect('/cart')

    order = Order(user=session['user'])
    db.session.add(order)
    db.session.flush()  # Get order.id

    for item in cart:
        order_item = OrderItem(
            med_name=item['name'],
            med_price=item['price'],
            order_id=order.id
        )
        db.session.add(order_item)

    db.session.commit()
    session['cart'] = []
    flash("Order placed successfully!")
    return redirect('/order-confirmation')

@app.route('/order-confirmation')
def order_confirmation():
    return render_template('order_confirmation.html')


@app.route('/remove/<int:id>')
def remove(id):
    med = Medicine.query.get(id)
    db.session.delete(med)
    db.session.commit()
    flash("Medicine removed!")
    return redirect('/admin')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)