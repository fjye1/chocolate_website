
from datetime import datetime, date
from models import db, Product, BoxSalesHistory, Box


MAX_DAILY_CHANGE = 0.05  # 5%



def update_dynamic_prices():
    today = date.today()
    boxes = Box.query.filter_by(is_active=True, dynamic_pricing_enabled=True).all()

    for box in boxes:
        if not box.expiration_date:
            continue  # skip if no expiry date

        days_left = (box.expiration_date.date() - today).days
        if days_left <= 0:
            continue  # box is expired

        quantity = box.quantity
        target_daily_sales = quantity / days_left if days_left > 0 else 1

        # Get today's sales
        sold_today = box.sold_today or 0

        # Calculate demand ratio and price multiplier
        demand_ratio = sold_today / target_daily_sales if target_daily_sales > 0 else 1
        price_multiplier = 1 + (demand_ratio - 1) * MAX_DAILY_CHANGE

        # Step 1: Calculate the new price
        new_price = box.price * price_multiplier

        # Step 2: Apply floor
        if box.floor_price and new_price < box.floor_price:
            new_price = box.floor_price

        # Step 3: Set pending price and sales target
        box.pending_price = round(new_price, 2)
        box.target_daily_sales = target_daily_sales



        # Save sales history
        sales_history = BoxSalesHistory(
            box_id =box.id,
            date=date.today(),
            sold_quantity=box.sold_today,
            sold_price=box.price,  # This is the price used during the day
            target_daily_sales=box.target_daily_sales,
            demand=box.sold_today/box.target_daily_sales,
            floor_price=box.floor_price
        )
        db.session.add(sales_history)

        # Step 4: Roll pending price into active price (e.g. at end of day)
        box.price = box.pending_price
        box.last_price_update = datetime.utcnow()

        # Optional: reset pending price until next calculation
        box.pending_price = None
        box.sold_today = 0



    db.session.commit()


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

