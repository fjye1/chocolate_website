from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify, make_response, current_app, \
    session
import csv

from sqlalchemy.orm import joinedload
from xhtml2pdf import pisa
import io

from flask_gravatar import Gravatar
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from forms import RegisterForm, LoginForm, AddAddress, ProductForm, CommentForm, StockForm, TrackingForm
from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin, \
    AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from sqlalchemy import cast, Date, literal
from datetime import datetime, timedelta, timezone, date
import stripe
import uuid

from dotenv import load_dotenv
import os
from extension import db

load_dotenv()

login_manager = LoginManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# TODO the section of code below is to link you to the render Database it won't work if you don't have a render database set up
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("RENDER_DATABASE_URL")

## this is the local database for app development only — use if in offline_db branch
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")

stripe.api_key = os.getenv("STRIPE_API_KEY")

db.init_app(app)

login_manager.init_app(app)
bootstrap = Bootstrap5(app)
ckeditor = CKEditor(app)

choc_email = os.getenv("CHOC_EMAIL")
choc_password = os.getenv("CHOC_PASSWORD")

from models import Cart, CartItem, Address, User, Orders, Product, Tag, OrderItem, Comment, ProductSalesHistory, \
    PriceAlert, SiteVisitCount, Tasks
from functions import update_dynamic_prices, MAX_DAILY_CHANGE

from tasks import simple_task


@app.route("/run_task", methods=["GET"])
def run_task():
    simple_task.delay()
    return "Task queued!"


LOG_PATH = 'logs/visit_log.txt'


@app.before_request
def count_visit():
    # Skip if already counted this session today
    if 'counted_today' in session:
        return None

    # Skip static files (css, js, images)
    if request.path.startswith('/static'):
        return None

    # Check if request looks like a bot
    user_agent = request.headers.get('User-Agent', '').lower()
    bot_signatures = [
        'go-http-client',  # Render health checks, Go bots
        'curl',  # command-line requests
        'bot',  # generic bot keyword
        'spider',  # web crawlers
        'python-requests'  # from server
    ]
    if any(sig in user_agent for sig in bot_signatures):
        # Don't log bots, but DO serve the page
        return None  # continue processing request

    # Log visit
    log_line = f"{datetime.now()} | Path: {request.path} | User-Agent: {request.headers.get('User-Agent')}\n"
    with open(LOG_PATH, 'a') as f:
        f.write(log_line)

    # Count visits
    today = date.today()
    counter = SiteVisitCount.query.get(today)
    if not counter:
        counter = SiteVisitCount(date=today, visit_count=1)
        db.session.add(counter)
    else:
        counter.visit_count += 1
    db.session.commit()

    # Mark so not counted again today
    session['counted_today'] = True


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


@app.route('/visit-log')
def visit_log():
    with open(LOG_PATH) as f:
        content = f.read()
    return f"<pre>{content}</pre>"


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

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


@app.route("/run-dynamic-pricing")
def run_dynamic_pricing():
    update_dynamic_prices()
    flash("Dynamic pricing updated successfully!", "success")
    return redirect(url_for("product_page"))


@app.route("/toggle-dynamic/<int:product_id>", methods=["POST"])
def toggle_dynamic_pricing(product_id):
    product = Product.query.get_or_404(product_id)
    product.dynamic_pricing_enabled = not product.dynamic_pricing_enabled
    db.session.commit()
    return redirect(request.referrer or url_for("admin_products"))


@app.route("/")
def home():
    if not session.get("portfolio_banner_shown"):
        flash("""
            <b>⚠️ Portfolio Demo Site</b><br>
    Please do not use real payment details.<br>
    Payments run in <b>Stripe test mode</b> only.
    <ul style="margin:6px 0 0 18px">
      <li>Visa: 4242 4242 4242 4242 (any future expiry, CVC, postcode)</li>
      <li>3D Secure test: 4000 0027 6000 3184</li>
    </ul>
    <b>No orders will be fulfilled.</b><br><br>

     <b>Features you can try:</b>
    <ul style="margin:6px 0 0 18px">
      <li>Place orders to see live <b>order updates</b> and <b>confirmation emails</b></li>
      <li>Dynamic <b>price alerts</b> & <b>daily price updates</b> (managed by an external server via SSH → PostgreSQL)</li>
    </ul>

     Interested in seeing more? <br>
    <b>Contact me if you’d like admin access</b> to explore the advanced features.<br>
    Mobile optimisation coming soon!
            """, "demo")
        session["portfolio_banner_shown"] = True
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
    selected_tags = request.args.getlist('tags')
    sort = request.args.get('sort')

    query = Product.query.filter_by(is_active=True)

    if product_key:
        tag = Tag.query.filter(Tag.name.ilike(f"%{product_key}%")).first()
        if tag:
            query = tag.products.filter_by(is_active=True)
        else:
            query = Product.query.filter(False)  # No match → empty
    elif selected_tags:
        query = (
            query
            .join(Product.tags)
            .filter(Tag.name.in_(selected_tags))
            .distinct()
        )

    # Apply sorting
    if sort == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        query = query.order_by(Product.price.desc())

    products = query.all()
    if sort == 'rating_desc':
        products.sort(key=lambda p: p.average_rating(), reverse=True)
    elif sort == 'rating_asc':
        products.sort(key=lambda p: p.average_rating())

    product_ids = [p.id for p in products]
    user_alerts = {}
    if current_user.is_authenticated:
        alerts = PriceAlert.query.filter(
            PriceAlert.user_id == current_user.id,
            PriceAlert.product_id.in_(product_ids)
        ).all()
        # Map product_id → alert
        user_alerts = {alert.product_id: alert for alert in alerts}

    all_tags = (
        db.session.query(Tag, func.count(Product.id).label("tag_count"))
        .join(Product.tags)
        .group_by(Tag.id)
        .order_by(func.count(Product.id).desc())
        .limit(10)
        .all()
    )

    return render_template(
        'Product/product_page.html',
        product_key=product_key,
        products=products,
        all_tags=all_tags,
        selected_tags=selected_tags,
        sort=sort,
        user_alerts=user_alerts
    )


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
        user_alert = None
        has_purchased = False
        already_commented = False
        can_comment = False
    else:
        user_alert = PriceAlert.query.filter_by(user_id=current_user.id, product_id=product.id).first()
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

    # Price history chart data
    start_date = date.today() - timedelta(days=28)
    recent_sales = [s for s in product.sales_history if s.date >= start_date]
    recent_sales.sort(key=lambda s: s.date)
    dates = [s.date.strftime('%Y-%m-%d') for s in recent_sales]
    prices = [s.sold_price for s in recent_sales]
    sales = [s.sold_quantity for s in recent_sales]

    return render_template("Product/product_details.html",
                           product=product,
                           form=comment_form,
                           can_comment=can_comment,
                           dates=dates,
                           prices=prices,
                           sales=sales,
                           user_alert=user_alert)


@app.route('/price-alert', methods=['POST'])
@login_required
def price_alert():
    target_price = float(request.form['target_price'])
    product_id = request.form['product_id']
    product = Product.query.get(product_id)
    expiry_days = 30
    expires_at = datetime.utcnow() + timedelta(days=expiry_days)

    if target_price < product.floor_price:
        flash(f"Please enter a price above £{product.floor_price:.2f}", "warning")
        return redirect(url_for('product_detail', product_id=product_id))

    alert = PriceAlert(
        user_id=current_user.id,
        product_id=product_id,
        target_price=target_price,
        expires_at=expires_at
    )
    db.session.add(alert)
    db.session.commit()

    flash(f"We will email you when {product.name} drops to £{target_price:.2f}!\n"
          f"You can manage your price alerts in your profile", 'success')

    return redirect(url_for('product_detail', product_id=product_id))


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
        # ✅ Merge guest basket into DB cart on login
        basket = session.get('basket', [])
        if basket:
            cart = get_user_cart(current_user.id)
            if not cart:
                cart = Cart(user_id=current_user.id, created_at=datetime.now(timezone.utc))
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
            session.pop('basket', None)  # optional: clear guest basket
        return redirect(url_for('home'))

    return render_template("login.html", form=form)


@app.route('/profile')
def profile():
    return render_template("Profile/profile.html")


@app.route('/profile/price_alerts')
def profile_price_alerts():
    alerts = current_user.price_alerts

    return render_template("Profile/profile_price_alerts.html", alerts=alerts)


@app.route('/delete-alert/<int:alert_id>', methods=['POST'])
@login_required
def delete_alert(alert_id):
    alert = PriceAlert.query.get_or_404(alert_id)

    if alert.user_id != current_user.id:
        abort(403)

    db.session.delete(alert)
    db.session.commit()
    flash("Price alert deleted.", "success")
    return redirect(url_for('profile_price_alerts'))


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

    # Check ownership
    if address.user_id != current_user.id:
        flash("You can't delete this address.", "danger")
        return redirect(url_for('profile_addresses'))

    # Soft delete instead of hard delete
    address.deleted = True
    db.session.commit()

    flash("Address removed from your profile.", "success")
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
    return redirect(url_for('profile_addresses'))


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
    print('Received data for PaymentIntent:', data)

    cart = data.get('cart', [])
    amount = 0
    for item in cart:
        price = item.get('price', 0)
        quantity = item.get('quantity', 0)
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
        metadata={
            'user_id': str(current_user.id),  # string because metadata values must be strings
            'cart': cart_str
        },
        automatic_payment_methods={'enabled': True}
    )

    print('Created PaymentIntent:', intent.id)
    return jsonify({'clientSecret': intent.client_secret})


@app.route('/success')
@login_required
def payment_success():
    payment_intent_id = request.args.get("payment_intent")
    if not payment_intent_id:
        flash("Payment info missing.", "danger")
        return redirect(url_for('home'))

    intent = stripe.PaymentIntent.retrieve(payment_intent_id)
    if intent.status != "succeeded":
        flash("Payment not completed.", "danger")
        return redirect(url_for('payment_failure'))

    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart or not cart.items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('home'))

    shipping_address = Address.query.filter_by(user_id=current_user.id, current_address=True).first()
    billing_address = Address.query.filter_by(user_id=current_user.id, current_address=True).first()

    if not shipping_address or not billing_address:
        flash("Missing address info.", "danger")
        return redirect(url_for('checkout'))

    order_id = f"ORD{int(datetime.now(timezone.utc).timestamp())}"
    total_amount = sum(item.product.price * item.quantity for item in cart.items)

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

    for item in cart.items:
        order_item = OrderItem(
            order=order,
            product=item.product,
            quantity=item.quantity,
            price_at_purchase=item.product.price
        )
        db.session.add(order_item)
        item.product.sold_today = (item.product.sold_today or 0) + item.quantity
        item.product.quantity -= item.quantity
        if item.product.quantity <= 0:
            item.product.is_active = False

    for item in cart.items:
        db.session.delete(item)

    db.session.commit()

    # save task to the database
    try:
        new_task = Tasks(
            task_name="send_invoice",
            arg1=order.order_id,
            arg2=order.user.email
        )
        db.session.add(new_task)
        db.session.commit()


    except Exception as e:
        print(f"[Invoice Queue Error]: {e}")
        flash("Order complete, but invoice could not be queued for email.", "warning")

    flash("Payment successful! Order placed.", "success")
    return render_template('payment_success.html', order=order)


@app.route('/invoice/<string:order_id>')
@login_required
def invoice(order_id):
    order = Orders.query.filter_by(order_id=order_id, user_id=current_user.id).first_or_404()
    return render_template('invoice.html', order=order)


@app.route('/internal-invoice/<string:order_id>/<string:secret>')
def internal_invoice(order_id, secret):
    if secret != os.getenv("SECRET"):
        abort(403)
    order = Orders.query.filter_by(order_id=order_id).first_or_404()
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
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func, cast, Date

    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=27)  # last 28 days including today

    if db.engine.name == 'sqlite':
        sales_data = (
            db.session.query(
                func.date(Orders.created_at).label("date"),
                func.sum(Orders.total_amount).label("sales")
            )
            .filter(func.date(Orders.created_at) >= start_date)
            .filter(func.date(Orders.created_at) <= today)
            .group_by(func.date(Orders.created_at))
            .order_by(func.date(Orders.created_at))
            .all()
        )
    else:
        sales_data = (
            db.session.query(
                cast(Orders.created_at, Date).label('date'),
                func.sum(Orders.total_amount).label('sales')
            )
            .filter(cast(Orders.created_at, Date) >= start_date)
            .filter(cast(Orders.created_at, Date) <= today)
            .group_by('date')
            .order_by('date')
            .all()
        )

    # Convert to lists for JS
    sales_dict = {d: s or 0 for d, s in sales_data}
    day_labels = [(start_date + timedelta(days=i)).strftime('%d %b') for i in range(28)]
    sales_values = [sales_dict.get(start_date + timedelta(days=i), 0) for i in range(28)]

    total_sales_last_28_days = sum(sales_values)
    orders = Orders.query.filter(Orders.tracking_number.is_(None)).all()

    return render_template(
        'Admin/admin.html',
        orders=orders,
        total=total_sales_last_28_days,
        day_labels=day_labels,
        sales_values=sales_values
    )


@app.route('/admin/order/<string:order_id>/add-tracking', methods=['GET', 'POST'])
def add_tracking(order_id):
    order = db.get_or_404(Orders, order_id)
    form = TrackingForm()

    if form.validate_on_submit():
        order.tracking_number = form.tracking_code.data
        db.session.commit()

        # Add task to DB instead of calling Celery
        new_task = Tasks(
            task_name="send_tracking",
            arg1=order.order_id,
            arg2=order.user.email,
            arg3=order.tracking_number
        )
        db.session.add(new_task)
        db.session.commit()

        flash("Tracking number added and task queued for sending email.", "success")
        return redirect(url_for('admin'))

    return render_template('Admin/add_tracking.html', form=form, order=order)


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


@app.route('/admin/archive')
@login_required
@admin_only
def admin_archive():
    orders = Orders.query.filter(Orders.tracking_number.isnot(None)).order_by(
        Orders.created_at.desc()
    ).all()

    return render_template("Admin/admin_archive.html", orders=orders)


@app.route('/admin/products')
@login_required
@admin_only
def admin_products():
    days_back = 28
    start_date = date.today() - timedelta(days=days_back)

    products = Product.query.options(joinedload(Product.sales_history)).all()
    now = datetime.utcnow()

    for product in products:
        # Calculate days left for this product
        if product.expiration_date:
            product.days_left = (product.expiration_date - now).days
        else:
            product.days_left = None

        # Filter recent sales
        product.recent_sales = [
            sale for sale in product.sales_history
            if sale.date >= start_date
        ]

        # Calculate totals
        total_revenue = 0
        total_cost = 0
        for sale in product.recent_sales:
            total_revenue += sale.sold_quantity * sale.sold_price
            total_cost += sale.sold_quantity * (product.floor_price or 0)

        product.profit = total_revenue - total_cost
        product.profit_percent = (product.profit / total_revenue * 100) if total_revenue > 0 else 0

        # Calculate average active price alert target_price
        avg_alert_price = db.session.query(func.avg(PriceAlert.target_price)).filter(
            PriceAlert.product_id == product.id,
            PriceAlert.expires_at > now
        ).scalar()
        product.avg_alert_price = round(avg_alert_price or 0, 2)

    # Sort products by profit_percent descending
    products.sort(key=lambda p: p.profit_percent, reverse=True)

    return render_template("Admin/admin_products.html", products=products)


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


@app.route('/admin/products/add/<int:product_id>', methods=['GET', 'POST'])
def admin_add_product(product_id):
    product = db.get_or_404(Product, product_id)
    form = StockForm()

    if form.validate_on_submit():
        product.quantity += form.quantity.data
        product.expiration_date = form.expiry_date.data
        product.floor_price = form.floor_price.data
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


from sqlalchemy import func


@app.route('/admin/users')
@login_required
@admin_only
def admin_users():
    total_orders = func.coalesce(func.sum(Orders.total_amount), 0).label('total_orders')
    if db.engine.name == 'sqlite':
        address = (
                func.coalesce(Address.street, '') + literal(', ') +
                func.coalesce(Address.city, '') + literal(', ') +
                func.coalesce(Address.postcode, '')
        ).label('address')
    else:
        address = func.concat_ws(', ', Address.street, Address.city, Address.postcode).label('address')

    query = (
        db.session.query(
            User.name,
            User.email,
            address,
            total_orders
        )
        .outerjoin(Orders, User.id == Orders.user_id)
        .outerjoin(Address, (User.id == Address.user_id) & (Address.current_address == True))
        .group_by(User.id, Address.street, Address.city, Address.postcode)
        .order_by(total_orders.desc())
    )

    results = query.all()
    return render_template("Admin/admin_users.html", results=results)


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


@app.route('/admin/statistics')
@login_required
@admin_only
def admin_statistics():
    end_date = date.today()
    start_date = end_date - timedelta(days=27)
    data = (
        SiteVisitCount.query
        .filter(SiteVisitCount.date >= start_date)
        .order_by(SiteVisitCount.date)
        .all()
    )

    labels = [record.date.strftime('%Y-%m-%d') for record in data]
    counts = [record.visit_count for record in data]

    return render_template('Admin/admin_statistics.html', labels=labels, counts=counts)


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
