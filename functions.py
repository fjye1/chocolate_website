from datetime import datetime, date

import requests

from models import db, Product, BoxSalesHistory, Box
from dotenv import load_dotenv
import os

load_dotenv()

MAX_DAILY_CHANGE = 0.05  # 5%

import os
import requests
import time

# Simple in-memory cache
_cached_rates = None
_cached_at = 0
CACHE_TTL = 10 * 60  # cache for 10 minutes

def precompute_products(products):
    for product in products:
        product._avg_rating = round(sum(c.rating for c in product.comments) / len(product.comments), 1) if product.comments else 0
        arrived_boxes = [b for b in product.boxes if b.is_active and b.shipment.has_arrived]
        product._lowest_box = min(arrived_boxes, key=lambda b: b.price_inr_unit) if arrived_boxes else None
    return products

def safe_commit():
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

def get_exchange_rates():
    global _cached_rates, _cached_at

    now = time.time()
    if _cached_rates and now - _cached_at < CACHE_TTL:
        return _cached_rates

    exchange_rates_key = os.getenv("EXCHANGE_RATES_API")
    url = f"http://api.exchangeratesapi.io/v1/latest?access_key={exchange_rates_key}"
    resp = requests.get(url)
    data = resp.json()

    gbp_per_eur = data["rates"]["GBP"]
    inr_per_eur = data["rates"]["INR"]

    # INR → GBP (1 INR = ? GBP)
    inr_to_gbp = gbp_per_eur / inr_per_eur

    # GBP → INR (1 GBP = ? INR)
    gbp_to_inr = inr_per_eur / gbp_per_eur

    # cache results
    _cached_rates = {"inr_to_gbp": inr_to_gbp, "gbp_to_inr": gbp_to_inr}
    _cached_at = now

    return _cached_rates


def inr_to_gbp(amount_inr):
    rates = get_exchange_rates()
    return amount_inr * rates["inr_to_gbp"]


def gbp_to_inr(amount_gbp):
    rates = get_exchange_rates()
    return amount_gbp * rates["gbp_to_inr"]



def update_dynamic_prices():
    today = date.today()
    boxes = Box.query.filter_by(dynamic_pricing_enabled=True, is_active=True).all()

    for box in boxes:
        if not box.expiration_date:
            continue  # skip if no expiry date

        days_left = (box.expiration_date - today).days
        if days_left <= 0:
            continue  # product is expired

        quantity = box.quantity
        target_daily_sales = quantity / days_left if days_left > 0 else 1

        # Get today's sales
        sold_today = box.sold_today or 0

        # Calculate demand ratio and price multiplier
        demand_ratio = sold_today / target_daily_sales if target_daily_sales > 0 else 1
        price_multiplier = 1 + (demand_ratio - 1) * MAX_DAILY_CHANGE

        # Step 1: Calculate the new price
        new_price = box.price_inr_unit * price_multiplier

        # Step 2: Apply floor
        if new_price < box.floor_price_inr_unit:
            new_price = box.floor_price_inr_unit

        # Step 3: Set pending price and sales target
        box.pending_price = round(new_price, 2)
        box.target_daily_sales = target_daily_sales

        # Save sales history
        sales_history = BoxSalesHistory(
            box_id=box.id,
            date=date.today(),
            sold_quantity=box.sold_today,
            sold_price=box.price_inr_unit,  # This is the price used during the day
            target_daily_sales=box.target_daily_sales,
            demand=box.sold_today/box.target_daily_sales,
            floor_price=box.floor_price_inr_unit
        )
        db.session.add(sales_history)

        # Step 4: Roll pending price into active price (e.g. at end of day)
        box.price_inr_unit = box.pending_price
        box.last_price_update = datetime.utcnow()

        # Optional: reset pending price until next calculation
        box.pending_price = None
        box.sold_today = 0

    try:
        db.session.commit()
        print("Commit successful!")
    except Exception as e:
        print(f"Commit failed: {e}")
        db.session.rollback()


class ProductService:
    @staticmethod
    def get_product_by_slug(slug):
        return Product.query.filter_by(slug=slug).first_or_404()
    """
    Service layer that abstracts Product data access.
    Routes talk to this service, not directly to the model.
    """

    @staticmethod
    def get_product_by_id(product_id):
        """Get a product with all its data (including dynamic pricing info)"""
        product = Product.query.get_or_404(product_id)
        # Right now, everything is in Product model
        # Later, you can fetch from DynamicPricing table here
        return product

    @staticmethod
    def get_product_detail(product_id):
        """
        Get product details as a dictionary.
        This completely hides the underlying structure.
        """
        product = Product.query.get_or_404(product_id)

        # Return a clean data structure
        return {
            'id': product.id,
            'name': product.name,
            'price': product.price,
            'description': product.description,
            'image': product.image,
            'weight': product.weight,
            'quantity': product.quantity,
            'is_active': product.is_active,
            'average_rating': product.average_rating(),
            # Dynamic pricing info
            'dynamic_pricing': {
                'enabled': product.dynamic_pricing_enabled,
                'expiration_date': product.expiration_date,
                'pending_price': product.pending_price,
                'target_daily_sales': product.target_daily_sales,
                'sold_today': product.sold_today,
                'last_price_update': product.last_price_update,
                'floor_price': product.floor_price
            }
        }


# ─── Delivery Area Configuration ──────────────────────────────────────────
VALID_PREFIXES   = ("39", "40")
EXCLUDED_PREFIXES = ("403",)      # Goa — no delivery
# ──────────────────────────────────────────────────────────────────────────

def can_deliver_to(pincode: str) -> bool:
    """
    Returns True if we deliver to the given PIN code.
    - Must start with 39 or 40
    - Must NOT start with 403 (Goa)
    """
    pincode = pincode.strip()

    if not pincode.isdigit() or len(pincode) != 6:
        return False

    if pincode.startswith(EXCLUDED_PREFIXES):
        return False

    return pincode.startswith(VALID_PREFIXES)


# ─── Fee Configuration ────────────────────────────────────────────────────
SHIPPING_FEE            = 99      # ₹ flat shipping fee
SHIPPING_FREE_THRESHOLD = 500     # ₹ order value for free shipping
CARD_FEE_FIXED          = 25      # ₹ fixed card processing fee
CARD_FEE_PERCENT        = 5.25    # % card processing fee (applied to subtotal + shipping)
# ──────────────────────────────────────────────────────────────────────────

def calculate_order_totals(cart_items):
    """
    Returns a dict with subtotal, shipping, card_fee, and grand_total.
    Card fee is applied to subtotal + shipping.
    Shipping is free on orders over SHIPPING_FREE_THRESHOLD.
    """
    subtotal = sum(float(item.price) * item.quantity for item in cart_items)
    shipping = 0 if subtotal >= SHIPPING_FREE_THRESHOLD else SHIPPING_FEE
    card_fee = round(CARD_FEE_FIXED + (subtotal + shipping) * (CARD_FEE_PERCENT / 100), 2)
    grand_total = round(subtotal + shipping + card_fee, 2)

    return {
        "subtotal":     round(subtotal, 2),
        "shipping":     shipping,
        "free_shipping": subtotal >= SHIPPING_FREE_THRESHOLD,
        "card_fee":     card_fee,
        "grand_total":  grand_total,
    }

# @staticmethod
# def get_similar_products(product_id, limit=4):
#     """Get products similar to the given product"""
#     product = Product.query.get_or_404(product_id)
#
#     results = (
#         db.session.query(Product)
#         .filter(Product.is_active == True)
#         .order_by(
#             Product.embedding.cosine_distance(literal(product.embedding))
#         )
#         .limit(limit)
#         .all()
#     )
#     return results

# @staticmethod
# def update_dynamic_pricing(product_id, **kwargs):
#     """
#     Update dynamic pricing fields.
#     When you migrate, this is where you'd update the new table.
#     """
#     product = Product.query.get_or_404(product_id)
#
#     # Right now: update Product model
#     if 'pending_price' in kwargs:
#         product.pending_price = kwargs['pending_price']
#     if 'sold_today' in kwargs:
#         product.sold_today = kwargs['sold_today']
#     if 'dynamic_pricing_enabled' in kwargs:
#         product.dynamic_pricing_enabled = kwargs['dynamic_pricing_enabled']
#     # ... etc
#
#     db.session.commit()
#     return product
#
# @staticmethod
# def get_dynamic_pricing_info(product_id):
#     """
#     Get ONLY dynamic pricing info.
#     After migration, this would query the DynamicPricing table.
#     """
#     product = Product.query.get_or_404(product_id)
#
#     return {
#         'product_id': product.id,
#         'dynamic_pricing_enabled': product.dynamic_pricing_enabled,
#         'pending_price': product.pending_price,
#         'target_daily_sales': product.target_daily_sales,
#         'sold_today': product.sold_today,
#         'last_price_update': product.last_price_update,
#         'floor_price': product.floor_price,
#         'expiration_date': product.expiration_date,
#         'date_added': product.date_added
#     }
