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
    boxes = Box.query.filter_by(is_active=True, dynamic_pricing_enabled=True).all()
    print(f"Found {len(boxes)} boxes")
    for box in boxes:
        print(f"Processing box {box.id}")
        if not box.expiration_date:
            print(f"  Skipped - no expiration date")
            continue

        days_left = (box.expiration_date - today).days
        if days_left <= 0:
            print(f"  Skipped - expired ({days_left} days)")
            continue

        quantity = box.quantity
        target_daily_sales = quantity / days_left if days_left > 0 else 1

        # Get today's sales
        sold_today = box.sold_today or 0

        # Calculate demand ratio and price multiplier
        demand_ratio = sold_today / target_daily_sales if target_daily_sales > 0 else 1
        price_multiplier = 1 + (demand_ratio - 1) * MAX_DAILY_CHANGE

        # Step 1: Calculate the new price
        new_price = box.price * price_multiplier

        # Step 2: Apply floor price
        if box.floor_price and new_price < box.floor_price:
            new_price = box.floor_price

        # Step 3: Save sales history BEFORE changing price or resetting sold_today
        sales_history = BoxSalesHistory(
            box_id=box.id,
            date=today,
            sold_quantity=sold_today,
            sold_price=box.price,  # price used during the day
            target_daily_sales=target_daily_sales,
            demand=(sold_today / target_daily_sales) if target_daily_sales > 0 else 0,
            floor_price=box.floor_price
        )
        db.session.add(sales_history)

        # Step 4: Update box price and reset for next day
        box.pending_price = round(new_price, 2)
        box.price = box.pending_price
        box.last_price_update = datetime.utcnow()
        box.target_daily_sales = target_daily_sales
        box.pending_price = None
        box.sold_today = 0

    try:
        db.session.commit()
        print("Commit successful!")
    except Exception as e:
        print(f"Commit failed: {e}")
        db.session.rollback()


class ProductService:
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
