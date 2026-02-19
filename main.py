# Standard library imports
import csv
import io
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone, date
from functools import wraps

# Third-party imports
import stripe
from PIL import Image, UnidentifiedImageError
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify, make_response, \
    current_app, session, g
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import LoginManager, login_user, current_user, login_required, logout_user, AnonymousUserMixin
from sqlalchemy import func, literal, event
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash, check_password_hash
from xhtml2pdf import pisa
from slugify import slugify

# Local application imports
from extension import db
from forms import RegisterForm, LoginForm, AddAddress, ProductForm, CommentForm, StockForm, TrackingForm, \
    ShipmentSentForm, BoxForm, ShipmentArrivalForm, AddToCartForm
from functions import update_dynamic_prices, ProductService, inr_to_gbp, gbp_to_inr, safe_commit, precompute_products,can_deliver_to
from models import Cart, CartItem, Address, User, Orders, Product, Tag, OrderItem, Comment, PriceAlert, \
    Tasks, Box, Shipment, SiteVisitCount
from tasks import simple_task

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# App configuration
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Enable this when using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Database configuration
# TODO the section of code below is to link you to the render
#  Database it won't work if you don't have a render database set up
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_INDIA")
# this is the local database for app development only — use if in offline_db branch
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 3,
    'max_overflow': 2,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}

# Initialize extensions
db.init_app(app)

# Connection monitoring setup (after db.init_app)
with app.app_context():
    engine = db.engine

    connection_count = 0
    count_lock = threading.Lock()


    @event.listens_for(engine, "connect")
    def receive_connect(dbapi_conn, connection_record):
        global connection_count
        with count_lock:
            connection_count += 1
            print(f"🟢 CONNECTION OPENED | Total active: {connection_count}")


    @event.listens_for(engine, "close")
    def receive_close(dbapi_conn, connection_record):
        global connection_count
        with count_lock:
            connection_count -= 1
            print(f"🔴 CONNECTION CLOSED | Total active: {connection_count}")


    def print_pool_status():
        pool = engine.pool
        print(f"\n📊 POOL STATUS:")
        print(f"   Pool size: {pool.size()}")
        print(f"   Checked out: {pool.checkedout()}")
        print(f"   Overflow: {pool.overflow()}")
        print(f"   Checked in: {pool.checkedin()}")
        print(f"   Total: {pool.size() + pool.overflow()}\n")


@app.route('/test_pool')
def test_pool():
    print_pool_status()
    # your database query here
    return "Check console"


login_manager = LoginManager()
login_manager.init_app(app)
bootstrap = Bootstrap5(app)
ckeditor = CKEditor(app)

# Third-party API keys
stripe.api_key = os.getenv("STRIPE_API_KEY")

# Application constants
choc_email = os.getenv("CHOC_EMAIL")
choc_password = os.getenv("CHOC_PASSWORD")
LOG_PATH = 'logs/visit_log.txt'


# Flask hooks and middleware
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()


@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.before_request
def count_visit():
    if 'counted_today' in session:
        return None

    if request.path.startswith((
            '/static', '/favicon', '/robots.txt', '/manifest.json'
    )) or request.path.endswith(('.css', '.js', '.png', '.jpg', '.ico')):
        return None

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log_line = f"{datetime.now()} | Path: {request.path} | IP: {ip}\n"
    with open(LOG_PATH, 'a') as f:
        f.write(log_line)

    # Only query DB once per process
    if not hasattr(g, 'today_counter'):
        today = date.today()
        g.today_counter = SiteVisitCount.query.get(today)
        if not g.today_counter:
            g.today_counter = SiteVisitCount(date=today, visit_count=1)
            db.session.add(g.today_counter)
        else:
            g.today_counter.visit_count += 1
        safe_commit()
    else:
        g.today_counter.visit_count += 1
        safe_commit()

    session['counted_today'] = True


@app.before_request
def load_cart():
    g.cart_items = []

    if current_user.is_authenticated:
        cart = Cart.query.filter_by(user_id=current_user.id).first()
        if cart:
            g.cart_items = [
                {'product_id': item.product_id, 'quantity': item.quantity}
                for item in cart.items
            ]
    else:
        g.cart_items = session.get('basket', [])


@app.context_processor
def inject_cart():
    return dict(cart_items=g.cart_items)


@app.route("/run_task", methods=["GET"])
def run_task():
    simple_task.delay()
    return "Task queued!"


def get_user_cart_cached(user_id):
    if not hasattr(g, 'cart'):
        g.cart = Cart.query.options(joinedload(Cart.items)).filter_by(user_id=user_id).first()
    return g.cart


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


# # ✅ must be run before adding data
# with app.app_context():
#     db.create_all()


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
        safe_commit()


# Uncomment and run once to load CSV
# with app.app_context():
#     load_csv_data()


@app.route("/run-dynamic-pricing")
def run_dynamic_pricing():
    update_dynamic_prices()

    flash("Dynamic pricing updated successfully!", "success")
    return redirect(url_for("product_page"))


@app.route("/toggle-dynamic/<int:product_id>", methods=["POST"])
def toggle_dynamic_pricing(product_id):
    product = ProductService.get_product_by_id(product_id)
    product.dynamic_pricing_enabled = not product.dynamic_pricing_enabled
    safe_commit()
    return redirect(request.referrer or url_for("admin_products"))

@app.route("/")
def home():
    if not session.get("portfolio_banner_shown"):
        flash("""
            <b>⚠️ Site Under Construction</b><br>
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
              <li>Dynamic <b>price alerts</b> & <b>daily price updates</b></li>
            </ul>
            """, "demo")
        session["portfolio_banner_shown"] = True

    # Fetch 3 random comments efficiently
    random_comments = Comment.query.order_by(func.random()).limit(3).all()

    admin = current_user.admin if current_user.is_authenticated else False

    # Preload boxes with shipments and comments to avoid lazy loading
    products = Product.query.options(
        db.joinedload(Product.boxes).joinedload(Box.shipment),
        db.selectinload(Product.comments)
    ).filter_by(is_active=True).all()

    products = precompute_products(products)

    sorted_products = sorted(products, key=lambda p: p._avg_rating, reverse=True)
    boxes = [b for p in products for b in p.boxes if b.is_active]  # Flatten active boxes

    user_alerts = {}
    if current_user.is_authenticated:
        product_ids = [p.id for p in products]
        alerts = PriceAlert.query.filter(
            PriceAlert.user_id == current_user.id,
            PriceAlert.product_id.in_(product_ids)
        ).all()
        user_alerts = {alert.product_id: alert for alert in alerts}

    return render_template(
        "home_page.html",
        products=products,
        admin=admin,
        comments=random_comments,
        sorted_products=sorted_products,
        boxes=boxes,
        user_alerts=user_alerts
    )

#/<slug>
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

    products = query.options(
        db.joinedload(Product.boxes).joinedload(Box.shipment),
        db.selectinload(Product.comments)
    ).all()

    # Precompute _avg_rating and _lowest_box for all products
    products = precompute_products(products)

    # Now sort using precomputed values
    if sort == 'price_asc':
        products.sort(key=lambda p: p._lowest_box.price_inr_unit if p._lowest_box else float('inf'))
    elif sort == 'price_desc':
        products.sort(key=lambda p: p._lowest_box.price_inr_unit if p._lowest_box else float('inf'), reverse=True)
    elif sort == 'rating_asc':
        products.sort(key=lambda p: p._avg_rating)
    elif sort == 'rating_desc':
        products.sort(key=lambda p: p._avg_rating, reverse=True)

    product_ids = [p.id for p in products]
    user_alerts = {}
    if current_user.is_authenticated:
        alerts = PriceAlert.query.filter(
            PriceAlert.user_id == current_user.id,
            PriceAlert.product_id.in_(product_ids)
        ).all()
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


@app.route("/product/<slug>", methods=["GET", "POST"])
def product_detail(slug):
    product = ProductService.get_product_by_slug(slug)  # need to add this method
    product_id = product.id  # keep this since it's used throughout

    results = (
        db.session.query(Product)
        .filter(Product.is_active)  # only active products
        .order_by(
            Product.embedding.cosine_distance(literal(product.embedding))
        )
        .limit(4)
        .all()
    )

    similar_products = results[1:4]
    similar_products = precompute_products(similar_products)

    comment_form = CommentForm()
    # Only boxes that have arrived and still have stock
    boxes = Box.query.join(Box.shipment) \
        .filter(Box.product_id == product.id, Shipment.has_arrived, Box.quantity > 0) \
        .order_by(Box.price_inr_unit.desc()) \
        .all()

    # Group by price and track total quantity + first expiry seen for that price
    price_groups = {}
    for box in boxes:
        if box.price_inr_unit not in price_groups:
            price_groups[box.price_inr_unit] = {
                'quantity': 0,
                'expiry': box.expiration_date,
                'box': box,  # add box reference
                'shipment': box.shipment  # add shipment reference
            }
        price_groups[box.price_inr_unit]['quantity'] += box.quantity

    # TODO understand the functionality of this line
    # # Ensure price_groups is ordered by price
    # price_groups = dict(sorted(price_groups.items()))

    # Find the cheapest box
    next_box = min(boxes, key=lambda b: b.price_inr_unit, default=None)

    add_to_cart_form = AddToCartForm(
        product_id=product.id,
        box_id=next_box.id if next_box else None,
        shipment_id=next_box.shipment_id if next_box else None
    )

    print("add_to_cart_form.box_id.data:", add_to_cart_form.box_id.data)
    print(next_box.id)

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
        safe_commit()
        return redirect(url_for('product_detail', slug=product.slug))


    start_date = date.today() - timedelta(days=28)

    # Collect all BoxSalesHistory for this product's boxes in the last 28 days
    recent_sales = []
    for box in product.boxes:
        recent_sales.extend([s for s in box.sales_history if s.date >= start_date])

    # Sort by date
    recent_sales.sort(key=lambda s: s.date)

    # Build lists
    dates = [s.date.strftime('%Y-%m-%d') for s in recent_sales]
    prices = [s.sold_price for s in recent_sales]
    sales = [s.sold_quantity for s in recent_sales]

    return render_template("Product/product_details.html",
                           product=product,
                           form=comment_form,
                           add_to_cart_form=add_to_cart_form,
                           can_comment=can_comment,
                           dates=dates,
                           prices=prices,
                           sales=sales,
                           user_alert=user_alert,
                           similar_products=similar_products,
                           price_groups=price_groups,
                           next_box=next_box
                           )


@app.route('/price-alert', methods=['POST'])
@login_required
def price_alert():
    target_price = float(request.form['target_price'])
    product_id = request.form['product_id']
    product = Product.query.get(product_id)

    # Find the lowest floor price among all boxes for this product
    lowest_floor_box = (
        Box.query
        .filter_by(product_id=product_id)
        .order_by(Box.floor_price_inr_unit.asc())
        .first()
    )

    if not lowest_floor_box:
        flash("No boxes found for this product.", "warning")
        return redirect(url_for('product_detail', product_id=product_id))

    expiry_days = 30
    expires_at = datetime.now(timezone.utc) + timedelta(days=expiry_days)

    # Use box.floor_price_inr_unit instead of product.floor_price_inr_unit
    if target_price < lowest_floor_box.floor_price_inr_unit:
        flash(f"Please enter a price above ₹{lowest_floor_box.floor_price_inr_unit:.2f}", "warning")
        return redirect(url_for('product_detail', product_id=product_id))

    alert = PriceAlert(
        user_id=current_user.id,
        product_id=product_id,
        target_price=target_price,
        expires_at=expires_at
    )
    db.session.add(alert)
    safe_commit()

    flash(
        f"We'll email you when {product.name} drops to ₹{target_price:.2f}! "
        f"You can manage alerts in your profile.",
        "success"
    )

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
        safe_commit()

        login_user(new_user)

        # ✅ Merge guest basket into DB cart
        basket = session.get('basket', [])
        if basket:
            cart = get_user_cart_cached(new_user.id)
            if not cart:
                cart = Cart(user_id=new_user.id, created_at=datetime.now(timezone.utc))
                db.session.add(cart)
                safe_commit()
            for b in basket:
                existing_item = CartItem.query.filter_by(cart_id=cart.id, product_id=b['product_id']).first()
                if existing_item:
                    existing_item.quantity += b['quantity']
                else:
                    new_item = CartItem(cart_id=cart.id, product_id=b['product_id'], quantity=b['quantity'])
                    db.session.add(new_item)
            safe_commit()
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
            cart = get_user_cart_cached(current_user.id)
            if not cart:
                cart = Cart(user_id=current_user.id, created_at=datetime.now(timezone.utc))
                db.session.add(cart)
                safe_commit()

            for b in basket:
                # Ensure the box exists
                box = Box.query.get(b.get('box_id'))
                if not box:
                    continue  # skip items with no valid box

                # Check for existing CartItem for this box
                existing_item = CartItem.query.filter_by(cart_id=cart.id, box_id=box.id).first()
                if existing_item:
                    new_qty = existing_item.quantity + b['quantity']
                    if new_qty > box.quantity:
                        new_qty = box.quantity  # cap to available stock
                    existing_item.quantity = new_qty
                else:
                    new_item = CartItem(
                        cart_id=cart.id,
                        box_id=box.id,
                        product_id=box.product_id,
                        shipment_id=box.shipment_id,
                        quantity=b['quantity'],
                        price=box.price_inr_unit
                    )
                    db.session.add(new_item)

            safe_commit()
            session.pop('basket', None)  # clear guest basket
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
    safe_commit()
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

        if not can_deliver_to(form.postcode.data):
            flash("Sorry, we don't currently deliver to that PIN code.", "danger")
            return render_template("Profile/profile_addresses.html", form=form)

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
        safe_commit()

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
    safe_commit()

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

    safe_commit()
    flash("Current address updated.", "success")
    return redirect(url_for('profile_addresses'))


@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    form = AddToCartForm()

    # if not form.validate_on_submit():
    #     flash("Invalid form submission.", "danger")
    #     return redirect(request.referrer)

    product_id = form.product_id.data
    box_id = form.box_id.data
    shipment_id = form.shipment_id.data
    quantity = form.quantity.data

    # Fetch the box (contains price + stock)
    box = Box.query.get_or_404(box_id)
    product = ProductService.get_product_by_id(product_id)

    # Stock check
    if quantity > box.quantity:
        flash(f"Only {box.quantity} items left in stock for this box.", "warning")
        return redirect(request.referrer or url_for('product_detail', product_id=product_id))

    # Logged-in user
    if current_user.is_authenticated:
        cart = get_user_cart_cached(current_user.id)
        if not cart:
            cart = Cart(user_id=current_user.id, created_at=datetime.now(timezone.utc))
            db.session.add(cart)
            safe_commit()

        cart_item = CartItem.query.filter_by(cart_id=cart.id, box_id=box.id).first()

        if cart_item:
            new_qty = cart_item.quantity + quantity
            if new_qty > box.quantity:
                flash(f"Only {box.quantity - cart_item.quantity} items left in stock.", "warning")
                return redirect(request.referrer or url_for('product_detail', product_id=product_id))
            cart_item.quantity = new_qty
        else:
            cart_item = CartItem(
                cart_id=cart.id,
                box_id=box.id,
                product_id=box.product_id,
                shipment_id=box.shipment_id,
                quantity=quantity,
                price=box.price_inr_unit
            )
            db.session.add(cart_item)

        safe_commit()

    # Guest user (session-based)
    else:
        basket = session.get('basket', [])
        found = False
        for item in basket:
            if item['box_id'] == box_id:
                new_qty = item['quantity'] + quantity
                if new_qty > box.quantity:
                    flash(f"Only {box.quantity - item['quantity']} items left in stock.", "warning")
                    return redirect(request.referrer or url_for('product_detail', product_id=product_id))
                item['quantity'] = new_qty
                found = True
                break

        if not found:
            basket.append({
                'product_id': product_id,
                'box_id': box_id,
                'shipment_id': shipment_id,
                'quantity': quantity,
                'price': float(box.price_inr_unit)
            })

        session['basket'] = basket

    flash(f"Added {quantity} of '{product.name}' to your cart.", "success")
    return redirect(request.referrer or url_for('cart'))


@app.route('/remove-cart-item/<int:item_id>', methods=['POST'])
@login_required
def remove_cart_item(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.cart.user_id != current_user.id:
        abort(403)
    db.session.delete(item)
    safe_commit()
    flash('Item removed from cart.')
    return redirect(url_for('cart'))


@app.route('/cart')
def cart():
    items = []
    total = 0

    if current_user.is_authenticated:
        cart = get_user_cart_cached(current_user.id)
        if cart and cart.items:
            for ci in cart.items:
                # Fail early if the box is missing
                if ci.box is None:
                    raise ValueError(f"CartItem {ci.id} has no associated Box!")

                # Price should never be None; if it is, we want it to fail
                if ci.price is None:
                    raise ValueError(f"CartItem {ci.id} has no price set!")

                items.append({
                    'product': ci.box.product,  # parent product
                    'box': ci.box,  # include box info
                    'quantity': ci.quantity,
                    'price': float(ci.price),  # box-specific price
                    'cart_item_id': ci.id
                })
                total += float(ci.price) * ci.quantity
    else:
        basket = session.get('basket', [])
        for b in basket:
            product = Product.query.get(b['product_id'])
            box = Box.query.get(b['box_id']) if b.get('box_id') else None

            if product is None:
                raise ValueError(f"Basket item with product_id {b.get('product_id')} not found")
            if box is None:
                raise ValueError(f"Basket item with box_id {b.get('box_id')} not found")
            if b.get('price') is None:
                raise ValueError(f"Basket item for box_id {b.get('box_id')} has no price")

            items.append({
                'product': product,
                'box': box,
                'quantity': b['quantity'],
                'price': float(b['price']),
                'cart_item_id': None
            })
            total += float(b['price']) * b['quantity']

    return render_template('cart.html', items=items, total=total)


@app.route('/admin/admin_cart', methods=['GET', 'POST'])
@login_required
@admin_only
def admin_cart():
    if not current_user.admin:
        abort(403)
    if current_user.is_authenticated:
        cart = get_user_cart_cached(current_user.id)
        items = []
        total = 0
        for ci in cart.items if cart and cart.items else []:
            items.append({
                'product': ci.box.product,
                'quantity': ci.quantity,
                'price': ci.box.price_inr_unit,
                'cart_item_id': ci.id
            })
            total += ci.box.price_inr_unit * ci.quantity
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

    return render_template("Admin/admin_cart.html", items=items, total=total)


@app.route('/checkout', methods=['POST', 'GET'])
@login_required
def checkout():
    cart = get_user_cart_cached(current_user.id)

    if not cart or not cart.items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('home'))

    # Soft stock check against box quantity
    for item in cart.items:
        if not item.box:
            flash(f"Box for '{item.box.name}' no longer exists.", "danger")
            return redirect(url_for('cart'))
        if item.quantity > item.box.quantity:
            flash(f"Not enough stock for '{item.box.name}' (Box: {item.box.name}). Only {item.box.quantity} left.",
                  "danger")
            return redirect(url_for('cart'))

    # Calculate total based on CartItem price (box-specific)
    total = sum(float(item.price) * item.quantity for item in cart.items)

    return render_template('checkout.html', total=total)


@app.route('/cart-data')
@login_required
def cart_data():
    cart = get_user_cart_cached(current_user.id)
    if not cart or not cart.items:
        data = {'items': [], 'total': 0}
    else:
        items = [
            {
                'product_id': item.box.product_id,  # <-- parent product
                'box_id': item.box_id,
                'shipment_id': item.shipment_id,
                'product_name': item.box.product.name,  # product name
                'quantity': item.quantity,
                'price': float(item.price),  # box-specific price
                'expiration_date': item.box.expiration_date.strftime('%Y-%m-%d') if item.box else None
            }
            for item in cart.items
        ]
        total = sum(item['price'] * item['quantity'] for item in items)
        data = {'items': items, 'total': total}

    print('Cart Data:', data)  # Server-side log
    return jsonify(data)


@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    data = request.json
    print('Received data for PaymentIntent:', data)

    cart_items = data.get('cart', [])
    amount = 0
    for item in cart_items:
        # Ensure we use the box-specific price
        price = item.get('price', 0)
        quantity = item.get('quantity', 0)
        try:
            price_paise = int(round(float(price) * 100))  # INR smallest unit
            qty = int(quantity)
            amount += price_paise * qty
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid price or quantity in cart'}), 400

    if amount <= 0:
        return jsonify({'error': 'Invalid total amount'}), 400

    import json
    cart_str = json.dumps(cart_items)

    intent = stripe.PaymentIntent.create(
        amount=amount,
        currency='inr',
        metadata={
            'user_id': str(current_user.id),  # must be string
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

    # Try to find existing order first
    order = Orders.query.filter_by(
        payment_intent_id=payment_intent_id,
        user_id=current_user.id
    ).first()

    # If no order exists, process it now (backward compatibility)
    if not order:
        order, error = process_paid_order(payment_intent_id, current_user.id)
        if error:
            flash(error, "danger")
            return redirect(url_for('payment_failure'))
        flash("Payment successful! Order placed.", "success")
    else:
        # Order already processed by webhook
        flash("Order confirmed!", "success")

    # Clean the URL to remove sensitive parameters
    return render_template('payment_success.html', order=order)


def process_paid_order(payment_intent_id, user_id):
    """
    Creates an order after payment is confirmed.
    Returns (order, error_message)
    """
    try:
        # Verify payment
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        if intent.status != "succeeded":
            return None, "Payment not completed"

        # Get user's cart
        cart = Cart.query.filter_by(user_id=user_id).first()
        if not cart or not cart.items:
            return None, "Cart is empty"

        # Get addresses
        shipping_address = Address.query.filter_by(user_id=user_id, current_address=True).first()
        billing_address = Address.query.filter_by(user_id=user_id, current_address=True).first()

        if not shipping_address or not billing_address:
            return None, "Missing address info"

        # Check if order already exists for this payment_intent
        existing_order = Orders.query.filter_by(payment_intent_id=payment_intent_id).first()
        if existing_order:
            print(f"Order already exists for payment_intent {payment_intent_id}")
            return existing_order, None

        order_id = f"ORD{int(datetime.now(timezone.utc).timestamp())}"
        total_amount = sum(float(item.price) * item.quantity for item in cart.items)
        payment_method = "live" if intent.livemode else "test"

        # Create order
        order = Orders(
            order_id=order_id,
            user_id=user_id,
            status="paid",
            total_amount=total_amount,
            payment_method=payment_method,
            payment_intent_id=payment_intent_id,  # IMPORTANT: Store this!
            shipping_address=shipping_address,
            billing_address=billing_address
        )
        db.session.add(order)

        # Create order items and adjust stock
        for item in cart.items:
            order_item = OrderItem(
                order=order,
                product_id=item.product_id,
                box_id=item.box_id,
                shipment_id=item.shipment_id,
                quantity=item.quantity,
                price_at_purchase=float(item.price)
            )
            db.session.add(order_item)

            if item.box:
                item.box.sold_today = (item.box.sold_today or 0) + item.quantity
                item.box.quantity -= item.quantity
                if item.box.quantity <= 0:
                    item.box.is_active = False

        # Clear cart
        for item in cart.items:
            db.session.delete(item)

        safe_commit()

        # Queue invoice
        try:
            new_task = Tasks(
                task_name="send_invoice",
                arg1=order.order_id,
                arg2=order.user.email
            )
            db.session.add(new_task)
            safe_commit()
        except Exception as e:
            print(f"[Invoice Queue Error]: {e}")

        return order, None

    except Exception as e:
        print(f"[Order Processing Error]: {e}")
        db.session.rollback()
        return None, str(e)


@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    # Get this from Stripe Dashboard -> Webhooks

    endpoint_secret = os.getenv["ENDPOINT_SECRET"]

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError:
        print("Invalid webhook payload")
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        print("Invalid webhook signature")
        return 'Invalid signature', 400

    # Handle payment success
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        payment_intent_id = payment_intent['id']

        # Get user_id from metadata (we'll add this in Step 8)
        user_id = payment_intent.get('metadata', {}).get('user_id')

        if not user_id:
            print(f"No user_id in payment_intent {payment_intent_id}")
            return 'Missing user_id', 400

        print(f"Processing order for payment_intent {payment_intent_id}, user {user_id}")

        order, error = process_paid_order(payment_intent_id, int(user_id))

        if error:
            print(f"Error processing order: {error}")
            # Don't return error - webhook will retry
            # Log it for manual review
        else:
            print(f"Order {order.order_id} created successfully via webhook")

    return 'Success', 200


@app.route('/invoice/<string:order_id>')
@login_required
def invoice(order_id):
    order = Orders.query.filter_by(order_id=order_id, user_id=current_user.id).first_or_404()
    return render_template('invoice.html', order=order)


def internal_auth():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {os.getenv('INTERNAL_API_TOKEN')}":
        abort(403)


@app.route('/internal-invoice/<string:order_id>')
def internal_invoice(order_id):
    internal_auth()

    order = Orders.query.filter_by(order_id=order_id).first_or_404()
    return render_template('invoice.html', order=order)


def serialize_order(order, url_root):
    return {
        "order_id": order.order_id,
        "created_at": order.created_at.isoformat(),
        "created_at_formatted": order.created_at.strftime('%b %d, %Y'),
        "status": order.status,
        "total_amount": float(order.total_amount),

        "shipping_address": {
            "street": order.shipping_address.street,
            "city": order.shipping_address.city,
            "postcode": order.shipping_address.postcode,
        } if order.shipping_address else None,

        "items": [
            {
                "product_name": item.product.name,
                "product_image": f"{url_root.rstrip('/')}/{item.product.pdf_image}",
                "box_id": item.box_id,
                "shipment_id": item.shipment_id,
                "quantity": item.quantity,
                "price_at_purchase": float(item.price_at_purchase),
                "line_total": float(item.quantity * item.price_at_purchase),
            }
            for item in order.order_items
        ]
    }


@app.route('/internal-invoice/<string:order_id>/json')
def internal_invoice_json(order_id):
    internal_auth()
    order = Orders.query.filter_by(order_id=order_id).first_or_404()
    return jsonify(serialize_order(order, request.url_root))


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
    product = ProductService.get_product_by_id(product_id)
    product.is_active = False  # Soft delete
    safe_commit()
    flash(f"Product '{product.name}' was soft deleted (hidden).", "warning")
    return redirect(url_for('admin_products'))


@app.route('/hard_delete_product/<int:product_id>', methods=['POST'])
@login_required
@admin_only
def hard_delete_product(product_id):
    product = ProductService.get_product_by_id(product_id)

    # Extra check: prevent hard delete if product has orders
    if product.order_items:
        flash("Cannot hard delete product with orders. Use soft delete.", "danger")
        return redirect(url_for('admin_products'))

    db.session.delete(product)
    safe_commit()
    flash(f"Product '{product.name}' was permanently deleted.", "success")
    return redirect(url_for('admin_products'))


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
        safe_commit()

        # Add task to DB instead of calling Celery
        new_task = Tasks(
            task_name="send_tracking",
            arg1=order.order_id,
            arg2=order.user.email,
            arg3=order.tracking_number
        )
        db.session.add(new_task)
        safe_commit()

        flash("Tracking number added and task queued for sending email.", "success")
        return redirect(url_for('admin'))

    return render_template('Admin/add_tracking.html', form=form, order=order)


@app.route("/create-shipment", methods=["GET", "POST"])
@login_required
@admin_only
def create_shipment():
    form = ShipmentSentForm()  # a simple form with only transit_cost and tariff_cost

    if form.validate_on_submit():
        shipment = Shipment(
            transit_cost=form.transit_cost.data,
        )
        db.session.add(shipment)
        safe_commit()

        flash("Shipment created — now add boxes!", "success")
        return redirect(url_for("add_box_to_shipment", shipment_id=shipment.id))

    return render_template("create_shipment.html", form=form)


@app.route("/shipment/<int:shipment_id>/add-box", methods=["GET", "POST"])
def add_box_to_shipment(shipment_id):
    shipment = Shipment.query.get_or_404(shipment_id)
    form = BoxForm()
    products = Product.query.all()

    # Set choices for the dropdown
    form.product_id.choices = [(p.id, p.name) for p in Product.query.all()]

    if form.validate_on_submit():
        # Get the actual Product object
        product = Product.query.get(form.product_id.data)
        if not product:
            flash("Selected product does not exist.", "danger")
            return redirect(url_for("add_box_to_shipment", shipment_id=shipment.id))

        box = Box(
            shipment_id=shipment.id,
            product_id=product.id,
            quantity=form.quantity.data,
            landing_price_gbp_box=form.uk_price_at_shipment.data,
            weight_per_unit=product.weight_per_unit,  # pulled from the Product
            expiration_date=form.expiration_date.data,
            dynamic_pricing_enabled=form.dynamic_pricing_enabled.data
        )
        db.session.add(box)
        safe_commit()

        flash("Box added to shipment!", "success")
        return redirect(url_for("add_box_to_shipment", shipment_id=shipment.id, products=products))

    boxes = Box.query.filter_by(shipment_id=shipment.id).all()
    return render_template("add_box_to_shipment.html", form=form, shipment=shipment, boxes=boxes)


@app.route("/admin/shipments")
@login_required
@admin_only
def view_shipments():
    shipments = Shipment.query.order_by(Shipment.date_created.desc()).all()
    return render_template("Admin/admin_shipments.html", shipments=shipments)


@app.route("/admin/shipments/<int:shipment_id>/arrived", methods=["GET", "POST"])
@login_required
@admin_only
def mark_shipment_arrived(shipment_id):
    shipment = Shipment.query.get_or_404(shipment_id)
    form = ShipmentArrivalForm()

    # Totals in GBP
    shipment_total_cost = sum(float(box.landing_price_gbp_box) for box in shipment.boxes)
    shipment_total_weight = sum(float(box.weight_per_unit) * box.quantity for box in shipment.boxes)
    shipment_total_cost_including_shipping = shipment_total_cost + float(shipment.transit_cost)

    tariff_cost_rupees = float(form.tariff_cost.data or 0.0)
    tariff_cost_gbp = inr_to_gbp(tariff_cost_rupees)

    if form.validate_on_submit():
        shipment.has_arrived = True
        shipment.date_arrived = datetime.now(timezone.utc)
        shipment.tariff_cost_rupees = tariff_cost_rupees
        shipment.tariff_cost_gbp = tariff_cost_gbp
        shipment.inr_to_gbp_exchange_rate = inr_to_gbp(1)

        for box in shipment.boxes:
            # Total box weight
            box_weight = float(box.weight_per_unit) * box.quantity

            # Allocate shipping proportionally by weight (in GBP)
            shipping_share_gbp = (box_weight / shipment_total_weight) * float(shipment.transit_cost)

            # Base cost incl. shipping (GBP)
            box_cost_incl_shipping_gbp = float(box.landing_price_gbp_box) + shipping_share_gbp

            # Allocate tariff proportionally (in GBP)
            tariff_share_gbp = (
                                       box_cost_incl_shipping_gbp / shipment_total_cost_including_shipping
                               ) * tariff_cost_gbp

            # Final total cost for the box (GBP)
            total_box_cost_gbp = box_cost_incl_shipping_gbp + tariff_share_gbp

            # Cost per bar (GBP)
            cost_per_bar_gbp = total_box_cost_gbp / box.quantity

            # Save GBP cost price per unit
            box.price_gbp_unit = round(cost_per_bar_gbp, 4)
            # save GBP price * 0.8 as price floor
            box.floor_price_gbp_unit = round(box.price_gbp_unit * 0.8, 2)  # 80% of cost

            # Convert cost-per-bar to INR for selling
            cost_per_bar_inr = gbp_to_inr(cost_per_bar_gbp)

            # SELLING PRICES (India-facing)
            box.landing_price_inr_box = round(cost_per_bar_inr * box.quantity, 2)
            box.floor_price_inr_unit = round(cost_per_bar_inr * 0.8, 2)  # 80% of cost
            box.price_inr_unit = round(cost_per_bar_inr * 1.15, 2)  # 15% margin

        safe_commit()
        flash(f"Shipment #{shipment.id} marked as arrived.", "success")
        return redirect(url_for("view_shipments"))

    return render_template("Admin/shipment_arrival.html", shipment=shipment, form=form)


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
        pdf_friendly_filename = None

        if image_file:
            # original extension (lowercase)
            ext = os.path.splitext(image_file.filename)[1].lower()
            # generate stable filename for original
            image_filename = f"{uuid.uuid4()}{ext}"
            UPLOAD_ROOT = "/var/www/uploads"
            save_dir = os.path.join(UPLOAD_ROOT, "choc")
            os.makedirs(save_dir, exist_ok=True)
            image_path = os.path.join(save_dir, image_filename)
            image_file.save(image_path)

            # default: use original if already PDF-friendly
            if ext in ['.jpg', '.jpeg', '.png']:
                pdf_friendly_filename = image_filename
            else:
                # try converting with Pillow (pillow-avif-plugin provides AVIF support)
                try:
                    png_fname = f"{uuid.uuid4()}.png"
                    png_path = os.path.join(save_dir, png_fname)

                    with Image.open(image_path) as img:
                        # convert to RGB to avoid issues with some formats / transparency
                        img = img.convert("RGB")
                        img.save(png_path, format='PNG')

                    pdf_friendly_filename = png_fname

                except UnidentifiedImageError:
                    # conversion failed — fall back to original (may break PDF generation)
                    current_app.logger.exception("Image conversion failed for %s", image_path)
                    pdf_friendly_filename = image_filename
                except Exception:
                    current_app.logger.exception("Unexpected error converting image %s", image_path)
                    pdf_friendly_filename = image_filename

        # Build relative paths stored in DB (same convention you're already using)
        rel_image = f"uploads/choc/{image_filename}" if image_filename else None
        rel_pdf_image = f"uploads/choc/{pdf_friendly_filename}" if pdf_friendly_filename else None

        new_product = Product(
            name=form.name.data,
            slug=slugify(form.name.data),
            description=form.description.data,
            weight_per_unit=float(form.weight_per_unit.data),
            image=rel_image,
            pdf_image=rel_pdf_image,
            ingredients=form.ingredients.data,
            allergens=json.dumps([a.strip() for a in (form.allergens.data or "").split(',') if a.strip()]),
            energy_kj=form.energy_kj.data,
            energy_kcal=form.energy_kcal.data,
            fat_g=form.fat_g.data,
            saturates_g=form.saturates_g.data,
            carbs_g=form.carbs_g.data,
            sugars_g=form.sugars_g.data,
            fibre_g=form.fibre_g.data,
            protein_g=form.protein_g.data,
            salt_g=form.salt_g.data
        )

        db.session.add(new_product)
        safe_commit()
        new_product.slug = f"{slugify(form.name.data)}-{new_product.id}"
        safe_commit()

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
    now = datetime.now(timezone.utc)

    products = Product.query.options(joinedload(Product.boxes).joinedload(Box.sales_history)).all()

    for product in products:
        active_boxes = [b for b in product.boxes if b.is_active]
        product.has_active_boxes = bool(active_boxes)
        product.total_quantity = sum(b.quantity for b in active_boxes)
        total_quantity = sum(b.quantity for b in active_boxes)
        product.avg_price = (
                sum(b.price_inr_unit * b.quantity for b in active_boxes) / total_quantity
        ) if active_boxes and total_quantity else 0
        earliest_box = min(active_boxes, key=lambda b: b.expiration_date, default=None)
        product.earliest_expiry = earliest_box.expiration_date if earliest_box else None
        product.days_left = (earliest_box.expiration_date - date.today()).days if earliest_box else None
        product.dynamic_pricing_enabled = any(b.dynamic_pricing_enabled for b in active_boxes)
        product.tag_names = ', '.join([t.name for t in product.tags])

        # Set a default expiration for boxes with none
        for box in active_boxes:
            if not box.expiration_date:
                box.expiration_date = date.today() + timedelta(days=30)  # use date.today()
            box.days_left = (box.expiration_date - date.today()).days  # also use date.today()

        # Aggregate sales from last `days_back` days
        recent_sales = []
        for box in active_boxes:
            recent_sales.extend([s for s in box.sales_history if s.date >= start_date])

        # Calculate totals
        product.total_revenue = sum(s.sold_quantity * s.sold_price for s in recent_sales)
        product.total_cost = sum(s.sold_quantity * (s.floor_price or 0) for s in recent_sales)

        product.profit = product.total_revenue - product.total_cost
        product.profit_percent = (product.profit / product.total_revenue * 100) if product.total_revenue > 0 else 0

        # Filter recent sales per product for display
        product.recent_sales = sorted(recent_sales, key=lambda s: s.date)

        # Average active price alert target_price
        avg_alert_price = db.session.query(func.avg(PriceAlert.target_price)).filter(
            PriceAlert.product_id == product.id,
            PriceAlert.expires_at > now
        ).scalar()
        product.avg_alert_price = round(avg_alert_price or 0, 2)

    # Sort products by profit_percent descending
    products.sort(key=lambda p: p.profit_percent, reverse=True)

    return render_template("Admin/admin_products.html", products=products, date=date, timedelta=timedelta)


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

        safe_commit()
        return redirect(url_for('admin_products'))

    return render_template('Admin/admin_products_edit.html', form=form, product=product)


# TODO determine if this is still used i dont think it is 24/11/2025
@app.route('/admin/products/add/<int:product_id>', methods=['GET', 'POST'])
def admin_add_product(product_id):
    product = db.get_or_404(Product, product_id)
    form = StockForm()

    if form.validate_on_submit():
        product.quantity += form.quantity.data
        product.expiration_date = form.expiry_date.data
        product.floor_price = form.floor_price.data
        safe_commit()
        return redirect(url_for('admin_products'))

    return render_template('Admin/admin_products_add.html', form=form, product=product)


@app.route('/admin/activate/<int:product_id>', methods=["POST"])
@login_required
@admin_only
def activate_product(product_id):
    product = ProductService.get_product_by_id(product_id)
    product.is_active = True
    safe_commit()
    flash(f"Product '{product.name}' activated.", "success")
    return redirect(request.referrer or url_for('admin_products'))


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
        .outerjoin(Address, (User.id == Address.user_id) & Address.current_address)
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


######### Footer links #########

# ─── Delivery Configuration ───────────────────────────────────────────────
DELIVERY_FEE = 99  # ₹ — fee charged per delivery
MIN_ORDER = 299  # ₹ — minimum order value to place an order


# ──────────────────────────────────────────────────────────────────────────

@app.route("/about")
def about():
    return render_template("Footerlinks/about.html")


@app.route("/contact")
def contact():
    return render_template("Footerlinks/contact.html")


@app.route("/delivery")
def delivery():
    return render_template("Footerlinks/delivery.html",
                           delivery_fee=DELIVERY_FEE,
                           min_order=MIN_ORDER, )

from flask import make_response, url_for
from datetime import datetime

# ─── Sitemap Configuration ─────────────────────────────────────────────────
SITE_URL = "https://www.regalchocolate.in"  # no trailing slash
# ──────────────────────────────────────────────────────────────────────────

@app.route("/sitemap.xml")
def sitemap():
    pages = []

    # ── Static pages ──────────────────────────────────────────────────────
    static_pages = ["home", "about", "contact", "delivery"]
    for route in static_pages:
        pages.append({
            "loc": SITE_URL + url_for(route),
            "priority": "1.0" if route == "index" else "0.6",
            "changefreq": "monthly",
        })

    # ── Product pages ─────────────────────────────────────────────────────
    products = Product.query.filter_by().all()  # adjust filter if needed
    for product in products:
        pages.append({
            "loc": SITE_URL + url_for("product_page", product_id=product.id),  # adjust endpoint name
            "priority": "0.9",
            "changefreq": "daily",
        })

    # ── Build XML ─────────────────────────────────────────────────────────
    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for page in pages:
        xml.append("  <url>")
        xml.append(f"    <loc>{page['loc']}</loc>")
        xml.append(f"    <changefreq>{page['changefreq']}</changefreq>")
        xml.append(f"    <priority>{page['priority']}</priority>")
        xml.append(f"    <lastmod>{datetime.utcnow().strftime('%Y-%m-%d')}</lastmod>")
        xml.append("  </url>")

    xml.append("</urlset>")

    response = make_response("\n".join(xml))
    response.headers["Content-Type"] = "application/xml"
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # use Render's assigned port if available
    app.run(host="0.0.0.0", port=port, debug=True)

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
