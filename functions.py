from datetime import datetime, date
from datetime import datetime, date
from models import db, Product, ProductSalesHistory

MAX_DAILY_CHANGE = 0.05  # 5%


def update_dynamic_prices():
    today = date.today()
    products = Product.query.filter_by(dynamic_pricing_enabled=True, is_active=True).all()

    for product in products:
        if not product.expiration_date:
            continue  # skip if no expiry date

        days_left = (product.expiration_date.date() - today).days
        if days_left <= 0:
            continue  # product is expired

        quantity = product.quantity
        target_daily_sales = quantity / days_left if days_left > 0 else 1

        # Get today's sales
        sold_today = product.sold_today or 0

        # Calculate demand ratio and price multiplier
        demand_ratio = sold_today / target_daily_sales if target_daily_sales > 0 else 1
        price_multiplier = 1 + (demand_ratio - 1) * MAX_DAILY_CHANGE

        # Apply to price
        new_price = product.price * price_multiplier
        product.target_daily_sales = target_daily_sales
        product.current_price = round(new_price, 2)
        product.price = product.current_price
        product.last_price_update = datetime.utcnow()

    db.session.commit()
