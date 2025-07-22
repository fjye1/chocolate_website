from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify, make_response, current_app,session
from flask_sqlalchemy import SQLAlchemy
import csv
from sqlalchemy import extract, label
from collections import defaultdict
import smtplib
from email.message import EmailMessage
from xhtml2pdf import pisa
import io
from email.message import EmailMessage
from flask_gravatar import Gravatar
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from forms import RegisterForm, LoginForm, AddAddress, ProductForm, CommentForm
from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin,AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.sql import func
from sqlalchemy import cast, Date
from datetime import datetime, timedelta, timezone
import stripe
import os, uuid
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os

load_dotenv()

# "CreatePostForm, CommentForm, ProductForm"


login_manager = LoginManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
stripe.api_key = os.getenv("STRIPE_API_KEY")
login_manager.init_app(app)

bootstrap = Bootstrap5(app)

ckeditor = CKEditor(app)
# TODO the section of code below is to link you to the render Database it wont work if you dont have a render database set up
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("RENDER_DATABASE_URL")

## this is the local database for app developement only use if in offline_db branch

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
db = SQLAlchemy(app)

choc_email = os.getenv("CHOC_EMAIL")

choc_password = os.getenv("CHOC_PASSWORD")


def get_user_cart(user_id):
    return Cart.query.filter_by(user_id=user_id).first()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if not current_user.admin:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

product_tags = db.Table(
    'product_tags',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    items = db.relationship('CartItem', backref='cart', lazy=True)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship('Product')


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    street = db.Column(db.String(255))
    city = db.Column(db.String(100))
    postcode = db.Column(db.String(20))
    current_address = db.Column(db.Boolean, default=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    addresses = db.relationship('Address', backref='user', lazy=True)  # one-to-many
    comments = db.relationship('Comment', backref='user', lazy=True)
    carts = db.relationship('Cart', backref='user', lazy=True)

    @property
    def current_address(self):
        return next((a for a in self.addresses if a.current_address), None)


class Orders(db.Model):
    order_id = db.Column(db.String(20), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='orders')
    order_date = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='pending')
    total_amount = db.Column(db.Float, nullable=False)
    total_pounds_sterling = db.Column(db.Float)
    payment_method = db.Column(db.String(50))
    shipping_address_id = db.Column(db.Integer, db.ForeignKey('address.id'))
    shipping_address = db.relationship('Address', foreign_keys=[shipping_address_id])
    billing_address_id = db.Column(db.Integer, db.ForeignKey('address.id'))
    billing_address = db.relationship('Address', foreign_keys=[billing_address_id])
    tracking_number = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, onupdate=func.now())


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(200))
    weight = db.Column(db.Integer)
    quantity = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    comments = db.relationship('Comment', backref='product', lazy=True)
    tags = db.relationship('Tag',secondary=product_tags,backref=db.backref('products', lazy='dynamic')
                           ,lazy='dynamic')
    def average_rating(self):
        avg = db.session.query(func.avg(Comment.rating)) \
            .filter(Comment.product_id == self.id).scalar()
        return round(avg or 0, 1)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(20), db.ForeignKey('orders.order_id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)
    price_at_purchase = db.Column(db.Float)  # optional

    product = db.relationship('Product', backref='order_items')
    order = db.relationship('Orders', backref='items')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    comment = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rating = db.Column(db.Integer, nullable=True)


# ✅ must be run before adding data
with app.app_context():
    db.create_all()


def load_csv_data():
    with open('Product_data.csv', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Optional: skip if already in DB
            if not Product.query.filter_by(name=row['name']).first():
                product = Product(
                    name=row['name'],
                    price=float(row['price']),
                    description=row['description'],
                    image=row['image'],
                    weight=int(row['weight']),
                    quantity=int(row['quantity'])
                )
                db.session.add(product)
        db.session.commit()


# Uncomment and run once to load CSV
with app.app_context():
    load_csv_data()


@app.route("/")
def home():
    products = Product.query.all()
    admin = current_user.admin if current_user.is_authenticated else False
    random_comments = Comment.query.order_by(func.random()).limit(3).all()
    products = Product.query.filter_by(is_active=True).all()
    sorted_products = sorted(products, key=lambda p: p.average_rating(), reverse=True)

    return render_template("home_page.html",
                           products=products,
                           admin=admin,
                           comments=random_comments,
                           sorted_products=sorted_products)

@app.route('/product')
def product_page():
    product_key = request.args.get('product')

    if product_key:
        tag = Tag.query.filter(Tag.name.ilike(f"%{product_key}%")).first()
        if tag:
            products = tag.products.filter_by(is_active=True).all()
        else:
            products = []
    else:
        products = Product.query.filter_by(is_active=True).all()

    return render_template('Product/product_page.html', product_key=product_key, products=products)



@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash("Please enter a search term.", "warning")
        return redirect(url_for('home'))

    # Example: search products by name or description (adjust your model)
    results = Product.query.filter(Product.name.ilike(f'%{query}%')).all()

    return render_template('Product/search_results.html', query=query, results=results)


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    comment_form = CommentForm()

    if isinstance(current_user, AnonymousUserMixin):
        has_purchased = False
        already_commented = False
        can_comment = False
    else:
        has_purchased = db.session.query(OrderItem).join(Orders).filter(
            Orders.user_id == current_user.id,
            OrderItem.product_id == product_id
        ).first() is not None

        already_commented = Comment.query.filter_by(
            user_id=current_user.id,
            product_id=product_id
        ).first() is not None

        can_comment = has_purchased and not already_commented

    if comment_form.validate_on_submit() and can_comment:
        new_comment = Comment(
            user_id=current_user.id,
            product_id=product_id,
            comment=comment_form.comment_text.data,
            rating=comment_form.rating.data
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('product_detail', product_id=product_id))

    return render_template("Product/product_details.html",
                           product=product,
                           form=comment_form,
                           can_comment=can_comment)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        # ✅ Merge guest basket into DB cart
        basket = session.get('basket', [])
        if basket:
            cart = get_user_cart(new_user.id)
            if not cart:
                cart = Cart(user_id=new_user.id, created_at=datetime.now(timezone.utc))
                db.session.add(cart)
                db.session.commit()
            for b in basket:
                existing_item = CartItem.query.filter_by(cart_id=cart.id, product_id=b['product_id']).first()
                if existing_item:
                    existing_item.quantity += b['quantity']
                else:
                    new_item = CartItem(cart_id=cart.id, product_id=b['product_id'], quantity=b['quantity'])
                    db.session.add(new_item)
            db.session.commit()
            session.pop('basket', None)

        return redirect(url_for("home"))
    return render_template("Register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # only run this on POST with valid data
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not check_password_hash(user.password, form.password.data):
            flash("Invalid email or password")
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('home'))

    return render_template("login.html", form=form)


@app.route('/profile')
def profile():
    return render_template("Profile/profile.html")


@app.route('/profile/orders')
def profile_orders():
    orders = Orders.query.filter_by(user_id=current_user.id).order_by(Orders.created_at.desc()).all()
    return render_template("Profile/profile_orders.html",
                           orders=orders)


@app.route('/profile/address', methods=["GET", "POST"])
@login_required
def profile_addresses():
    form = AddAddress()
    if form.validate_on_submit():
        # Unset all current addresses for the user
        Address.query.filter_by(user_id=current_user.id).update({'current_address': False})

        # Add the new address and mark it as current
        address = Address(
            user_id=current_user.id,
            street=form.address.data,
            city=form.city.data,
            postcode=form.postcode.data,
            current_address=True
        )
        db.session.add(address)
        db.session.commit()

        flash("Address saved and set as current!", "success")
        return redirect(url_for('profile'))

    return render_template("Profile/profile_addresses.html", form=form)

@app.route('/profile/address/delete/<int:address_id>', methods=['POST'])
@login_required
def delete_address(address_id):
    address = Address.query.get_or_404(address_id)
    if address.user_id != current_user.id:
        flash("You can't delete this address.", "danger")
        return redirect(url_for('profile_addresses'))
    db.session.delete(address)
    db.session.commit()
    flash("Address deleted.", "success")
    return redirect(url_for('profile_addresses'))

@app.route('/set-current-address/<int:address_id>', methods=['POST'])
@login_required
def set_current_address(address_id):
    address = Address.query.filter_by(id=address_id, user_id=current_user.id).first_or_404()

    # Set all user's addresses to False
    Address.query.filter_by(user_id=current_user.id).update({'current_address': False})

    # Set selected address to True
    address.current_address = True

    db.session.commit()
    flash("Current address updated.", "success")
    return redirect(url_for('profile'))


@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    product_id = int(request.form['product_id'])
    quantity = int(request.form['quantity'])

    product = Product.query.get_or_404(product_id)

    if current_user.is_authenticated:
        # Logged-in user: save in DB cart
        cart = get_user_cart(current_user.id)
        if not cart:
            cart = Cart(user_id=current_user.id, created_at=datetime.now(timezone.utc))
            db.session.add(cart)
            db.session.commit()

        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product_id).first()

        current_qty = cart_item.quantity if cart_item else 0
        new_total_qty = current_qty + quantity

        if new_total_qty > product.quantity:
            flash(f"Only {product.quantity - current_qty} items left in stock. Please adjust quantity.", "warning")
            return redirect(request.referrer or url_for('product_detail', product_id=product_id))

        if cart_item:
            cart_item.quantity = new_total_qty
        else:
            cart_item = CartItem(cart_id=cart.id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)

        db.session.commit()

    else:
        # Guest user: save in session basket
        basket = session.get('basket', [])

        for item in basket:
            if item['product_id'] == product_id:
                current_qty = item['quantity']
                new_total_qty = current_qty + quantity
                if new_total_qty > product.quantity:
                    flash(f"Only {product.quantity - current_qty} items left in stock. Please adjust quantity.",
                          "warning")
                    return redirect(request.referrer or url_for('product_detail', product_id=product_id))
                item['quantity'] = new_total_qty
                break
        else:
            if quantity > product.quantity:
                flash(f"Only {product.quantity} items left in stock. Please adjust quantity.", "warning")
                return redirect(request.referrer or url_for('product_detail', product_id=product_id))
            basket.append({
                'product_id': product_id,
                'quantity': quantity,
                'price': float(product.price)
            })

        session['basket'] = basket

    flash(f"Added {quantity} of the product to your cart.", "success")
    return redirect(request.referrer or url_for('cart'))


@app.route('/remove-cart-item/<int:item_id>', methods=['POST'])
@login_required
def remove_cart_item(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.cart.user_id != current_user.id:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    flash('Item removed from cart.')
    return redirect(url_for('cart'))


@app.route('/cart')
def cart():
    if current_user.is_authenticated:
        cart = get_user_cart(current_user.id)
        items = []
        total = 0
        for ci in cart.items if cart and cart.items else []:
            items.append({
                'product': ci.product,
                'quantity': ci.quantity,
                'price': ci.product.price,
                'cart_item_id': ci.id
            })
            total += ci.product.price * ci.quantity
    else:
        basket = session.get('basket', [])
        items = []
        total = 0
        for b in basket:
            product = Product.query.get(b['product_id'])
            if product:
                items.append({
                    'product': product,
                    'quantity': b['quantity'],
                    'price': b['price'],
                    'cart_item_id': None  # no DB id
                })
                total += b['price'] * b['quantity']

    return render_template('cart.html', items=items, total=total)



@app.route('/checkout', methods=['POST', 'GET'])
@login_required
def checkout():
    cart = get_user_cart(current_user.id)

    if not cart or not cart.items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('home'))

    # Soft stock check
    for item in cart.items:
        if item.quantity > item.product.quantity:
            flash(f"Not enough stock for '{item.product.name}'. Only {item.product.quantity} left in stock.", "danger")
            return redirect(url_for('cart'))

    total = sum(item.product.price * item.quantity for item in cart.items)
    return render_template('checkout.html', total=total)

@app.route('/cart-data')
@login_required
def cart_data():
    cart = get_user_cart(current_user.id)
    if not cart or not cart.items:
        data = {'items': [], 'total': 0}
    else:
        items = [
            {
                'product_id': item.product_id,
                'name': item.product.name,
                'quantity': item.quantity,
                'price': item.product.price
            } for item in cart.items
        ]
        total = sum(item['price'] * item['quantity'] for item in items)
        data = {'items': items, 'total': total}

    print('Cart Data:', data)  # <-- Server-side log here
    return jsonify(data)


@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    data = request.json
    print('Received data for PaymentIntent:', data)  # Server log

    cart = data.get('cart', [])
    amount = 0
    for item in cart:
        price = item.get('price', 0)
        quantity = item.get('quantity', 0)
        # Defensive cast and conversion to pence
        try:
            price_pence = int(round(float(price) * 100))
            qty = int(quantity)
            amount += price_pence * qty
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid price or quantity in cart'}), 400

    if amount <= 0:
        return jsonify({'error': 'Invalid total amount'}), 400

    import json
    cart_str = json.dumps(cart)

    intent = stripe.PaymentIntent.create(
        amount=amount,
        currency='gbp',
        metadata={'cart': cart_str},
        automatic_payment_methods={'enabled': True}
    )
    print('Created PaymentIntent:', intent.id)
    return jsonify({'clientSecret': intent.client_secret})


@app.route('/payment-success')
@login_required
def payment_success():
    # Get current user's cart
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart or not cart.items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('home'))

    # You may want to get default or most recent address
    shipping_address = Address.query.filter_by(user_id=current_user.id).first()
    billing_address = Address.query.filter_by(user_id=current_user.id).first()

    if not shipping_address or not billing_address:
        flash("Missing address information.", "danger")
        return redirect(url_for('checkout'))

    # Generate order ID (simple version)
    order_id = f"ORD{int(datetime.now(timezone.utc).timestamp())}"

    # Calculate total
    total_amount = sum(item.product.price * item.quantity for item in cart.items)

    # Create order
    order = Orders(
        order_id=order_id,
        user_id=current_user.id,
        status="paid",
        total_amount=total_amount,
        payment_method="test_mode",
        shipping_address=shipping_address,
        billing_address=billing_address
    )
    db.session.add(order)

    # Create order items
    for item in cart.items:
        order_item = OrderItem(
            order=order,
            product=item.product,
            quantity=item.quantity,
            price_at_purchase=item.product.price
        )
        db.session.add(order_item)

    # Clear the cart
    for item in cart.items:
        db.session.delete(item)

    # Reduce stock for each ordered product
    for item in order.items:
        item.product.quantity -= item.quantity
        if item.product.quantity <= 0:
            item.product.is_active = False

    # Final commit
    db.session.commit()

    # Generate invoice HTML
    invoice_html = render_template('invoice.html', order=order)

    # Render PDF
    pdf_stream = io.BytesIO()
    pisa.CreatePDF(invoice_html, dest=pdf_stream, link_callback=link_callback)
    pdf = pdf_stream.getvalue()

    # Email setup
    msg = EmailMessage()
    msg['Subject'] = f"Your Invoice - {order.order_id}"
    msg['From'] = "your_email@example.com"
    msg['To'] = current_user.email
    msg.set_content("Thanks for your order! Your invoice is attached.")

    # Attach PDF
    msg.add_attachment(pdf, maintype='application', subtype='pdf', filename=f"Invoice_{order.order_id}.pdf")

    # Send the email (Gmail example, requires app password or enabling less secure apps)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(user=choc_email, password=choc_password)
        smtp.send_message(msg)

    flash("Payment successful! Your order has been placed.", "success")
    return render_template('payment_success.html', order=order)


@app.route('/invoice/<string:order_id>')
@login_required
def invoice(order_id):
    order = Orders.query.filter_by(order_id=order_id, user_id=current_user.id).first_or_404()
    return render_template('invoice.html', order=order)


@app.route('/payment-failure')
def payment_failure():
    return render_template('payment_failure.html')


def link_callback(uri, rel):
    # Convert /static/... to the real filesystem path
    if uri.startswith('/static/'):
        path = os.path.join(current_app.root_path, uri[1:])
        return path
    return uri


@app.route('/invoice/<order_id>/download')
@login_required
def download_invoice(order_id):
    order = Orders.query.filter_by(order_id=order_id, user_id=current_user.id).first_or_404()
    html = render_template('invoice.html', order=order)

    result = io.BytesIO()
    pisa_status = pisa.CreatePDF(
        html, dest=result, link_callback=link_callback
    )

    if pisa_status.err:
        return "PDF generation failed", 500

    response = make_response(result.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=invoice_{order_id}.pdf'
    return response


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/soft_delete_product/<int:product_id>', methods=['POST'])
@login_required
@admin_only
def soft_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_active = False  # Soft delete
    db.session.commit()
    flash(f"Product '{product.name}' was soft deleted (hidden).", "warning")
    return redirect(url_for('home'))


@app.route('/hard_delete_product/<int:product_id>', methods=['POST'])
@login_required
@admin_only
def hard_delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Extra check: prevent hard delete if product has orders
    if product.order_items:
        flash("Cannot hard delete product with orders. Use soft delete.", "danger")
        return redirect(url_for('home'))

    db.session.delete(product)
    db.session.commit()
    flash(f"Product '{product.name}' was permanently deleted.", "success")
    return redirect(url_for('home'))


@app.route('/admin')
@login_required
@admin_only
def admin():
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns
    from io import BytesIO
    import base64
    import pandas as pd
    from collections import defaultdict
    from sqlalchemy import func, extract

    # Use timezone-aware UTC now
    one_week_ago = datetime.now(timezone.utc).date() - timedelta(days=6)  # last 7 days including today
    today = datetime.now(timezone.utc).date()

    # TODO this section is for the render database(Postgres) it will not work on local
    # sales_data = (
    #     db.session.query(
    #         cast(Orders.created_at, Date).label('date'),
    #         func.sum(Orders.total_amount).label('sales')
    #     )
    #     .filter(cast(Orders.created_at, Date) >= one_week_ago)
    #     .filter(cast(Orders.created_at, Date) <= today)
    #     .group_by('date')
    #     .order_by('date')
    #     .all()
    # )
    ## TODO this section is for local database(SQLite) it will not work on render
    sales_data = (
        db.session.query(
            func.date(Orders.created_at).label("date"),  # ← this works better than cast
            func.sum(Orders.total_amount).label("sales")
        )
        .filter(func.date(Orders.created_at) >= one_week_ago)
        .filter(func.date(Orders.created_at) <= today)
        .group_by(func.date(Orders.created_at))
        .order_by(func.date(Orders.created_at))
        .all()
    )

    sales_dict = {
        datetime.strptime(date_str, '%Y-%m-%d').date(): sales
        for date_str, sales in sales_data
    }

    day_dates = [one_week_ago + timedelta(days=i) for i in range(7)]
    day_labels = [d.strftime('%d %b') for d in day_dates]  # e.g. 15 Jun

    sales_values = [sales_dict.get(d, 0) for d in day_dates]

    df = pd.DataFrame({
        'Day': day_labels,
        'Sales': sales_values
    })
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df, x='Day', y='Sales', color='skyblue')
    plt.xticks(rotation=45)
    plt.title("Last Week's Sales")
    buf = BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    buf.seek(0)
    chart_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()

    total_sales_last_week = sum(s or 0 for s in sales_dict.values())
    orders = Orders.query.order_by(Orders.created_at.desc()).all()

    return render_template('Admin/admin.html', chart=chart_base64, orders=orders, total=total_sales_last_week)



@app.route('/create-product', methods=['GET', 'POST'])
@login_required
@admin_only
def create_product():
    if not current_user.admin:
        abort(403)

    form = ProductForm()
    if form.validate_on_submit():
        image_file = form.image.data
        image_filename = None

        if image_file:
            ext = os.path.splitext(image_file.filename)[1]
            image_filename = f"{uuid.uuid4()}{ext}"
            save_dir = 'static/images/choc'
            os.makedirs(save_dir, exist_ok=True)
            image_path = os.path.join(save_dir, image_filename)
            image_file.save(image_path)

        # Save the product to the database with the image path
        new_product = Product(
            name=form.name.data,
            price=float(form.price.data),
            description=form.description.data,
            weight=float(form.weight.data),
            quantity=(form.quantity.data),
            image=f'images/choc/{image_filename}' if image_filename else None
        )
        db.session.add(new_product)
        db.session.commit()

        flash('Product created!')
        return redirect(url_for('home'))

    return render_template('create_product.html', form=form)


@app.route('/admin/products')
@login_required
@admin_only
def admin_products():
    products = Product.query.order_by(Product.quantity.asc()).all()
    return render_template("Admin/admin_products.html",
                           products=products)


@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
def admin_edit_product(product_id):
    product = db.get_or_404(Product, product_id)
    form = ProductForm(obj=product)

    # Pre-fill tags field as a string
    if request.method == 'GET':
        form.tags.data = ', '.join([tag.name for tag in product.tags])

    if form.validate_on_submit():
        # Manually populate everything except the tags field
        product.name = form.name.data
        product.price = form.price.data
        product.description = form.description.data
        product.image = form.image.data
        product.weight = form.weight.data
        product.quantity = form.quantity.data

        # Handle tags manually
        tag_names = [name.strip() for name in form.tags.data.split(',') if name.strip()]
        tag_objects = []
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
            tag_objects.append(tag)

        product.tags = tag_objects

        db.session.commit()
        return redirect(url_for('admin_products'))

    return render_template('Admin/admin_products_edit.html', form=form, product=product)

@app.route('/admin/products/add/<int:product_id>', methods=['GET','POST'])
def admin_add_product(product_id):
    product = db.get_or_404(Product, product_id)
    form = ProductForm()

    if form.validate_on_submit():
        product.quantity += form.quantity.data
        db.session.commit()
        return redirect(url_for('admin_products'))

    return render_template('Admin/admin_products_add.html', form=form, product=product)



@app.route('/admin/activate/<int:product_id>', methods=["POST"])
@login_required
@admin_only
def activate_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_active = True
    db.session.commit()
    flash(f"Product '{product.name}' activated.", "success")
    return redirect(request.referrer or url_for('admin_products'))


@app.route('/admin/users')
@login_required
@admin_only
def admin_users():
    total_orders = func.coalesce(func.sum(Orders.total_amount), 0).label('total_orders')
    address = (Address.street + ', ' + Address.city + ', ' + Address.postcode).label('address')
    query = (
        db.session.query(
            User.name,
            User.email,
            address,
            total_orders
        )
        .outerjoin(Orders, User.id == Orders.user_id)
        .outerjoin(Address, (User.id == Address.user_id) & (Address.current_address == True))
        .group_by(User.id)
        .order_by(total_orders.desc())
    )
    results = query.all()
    return render_template("Admin/admin_users.html",results = results)


@app.route('/admin/reports')
@login_required
@admin_only
def admin_reports():
    return render_template("Admin/admin_reports.html")


@app.route('/admin/support')
@login_required
@admin_only
def admin_support():
    return render_template("Admin/admin_support.html")


@app.route('/admin/settings')
@login_required
@admin_only
def admin_settings():
    return render_template("Admin/admin_settings.html")


if __name__ == "__main__":
    app.run(debug=True)

"https://cococart.in/"
"https://snackzack.com/"
"free shipping over 999 roupes"
"https://www.chocoliz.com/"
"https://snackstar.in/"
"https://www.bigbasket.com/"
"https://www.fnp.com/"
"https://www.zeptonow.com/"

"https://www.hancocks.co.uk/"
"https://www.hswholesalesweets.co.uk/"
