import os
import sys
from datetime import datetime, date

# Add your project to the path so we can import from it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import your app and the function
from main import app, db  # Replace 'your_main_app_file' with your actual main file name
from models import Box, BoxSalesHistory

MAX_DAILY_CHANGE = 0.05  # 5%

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
        new_price = box.price_inr * price_multiplier

        # Step 2: Apply floor
        if new_price < box.floor_price_inr:
            new_price = box.floor_price_inr

        # Step 3: Set pending price and sales target
        box.pending_price = round(new_price, 2)
        box.target_daily_sales = target_daily_sales

        # Save sales history
        sales_history = BoxSalesHistory(
            box_id=box.id,
            date=date.today(),
            sold_quantity=box.sold_today,
            sold_price=box.price_inr,  # This is the price used during the day
            target_daily_sales=box.target_daily_sales,
            demand=box.sold_today/box.target_daily_sales,
            floor_price=box.floor_price_inr
        )
        db.session.add(sales_history)

        # Step 4: Roll pending price into active price (e.g. at end of day)
        box.price_inr = box.pending_price
        box.last_price_update = datetime.utcnow()

        # Optional: reset pending price until next calculation
        box.pending_price = None
        box.sold_today = 0

    db.session.commit()
    print(f"Updated pricing for {len(boxes)} boxes at {datetime.utcnow()}")

if __name__ == "__main__":
    with app.app_context():
        update_dynamic_prices()