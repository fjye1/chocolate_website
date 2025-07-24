from datetime import datetime, date

MAX_DAILY_CHANGE = 0.05  # 5%

def update_dynamic_prices():
    today = date.today()
    products = Product.query.filter_by(dynamic_pricing_enabled=True, is_active=True).all()

    for product in products:
        # Get today's sales history entry
        sales_today = SalesHistory.query.filter_by(product_id=product.id, date=today).first()

        sold_today = sales_today.units_sold if sales_today else 0
        target = product.target_daily_sales or 1  # avoid div by zero

        # Calculate demand factor (limit to avoid crazy spikes)
        demand_factor = target / sold_today if sold_today > 0 else 2  # if zero sold, increase price slowly
        demand_factor = max(1 - MAX_DAILY_CHANGE, min(demand_factor, 1 + MAX_DAILY_CHANGE))

        # Calculate new price (smooth the change)
        new_price = product.current_price * demand_factor

        # Cap the price change within max daily change
        max_increase = product.current_price * (1 + MAX_DAILY_CHANGE)
        max_decrease = product.current_price * (1 - MAX_DAILY_CHANGE)

        new_price = min(max(new_price, max_decrease), max_increase)

        # Update product
        product.current_price = round(new_price, 2)  # round to 2 decimal places
        product.last_price_update = datetime.utcnow()

    db.session.commit()