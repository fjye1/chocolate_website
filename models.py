import datetime
from datetime import datetime, timezone, timedelta

from flask_login import UserMixin
from pgvector.sqlalchemy import Vector
from sqlalchemy.sql import func

from extension import db


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    street = db.Column(db.String(255))
    city = db.Column(db.String(100))
    postcode = db.Column(db.String(20))
    current_address = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    items = db.relationship('CartItem', backref='cart', lazy=True)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    box_id = db.Column(db.Integer, db.ForeignKey('box.id'))  # <-- new
    shipment_id = db.Column(db.Integer, db.ForeignKey('shipment.id'))  # <-- new
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Numeric(10, 2))  # optional, store price at time of add-to-cart

    product = db.relationship('Product')
    box = db.relationship('Box')
    shipment = db.relationship('Shipment')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    comment = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    rating = db.Column(db.Integer, nullable=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    addresses = db.relationship('Address', backref='user', lazy=True)  # one-to-many
    comments = db.relationship('Comment', backref='user', lazy=True)
    carts = db.relationship('Cart', backref='user', lazy=True)
    price_alerts = db.relationship('PriceAlert', back_populates='user')

    @property
    def current_address(self):
        return next((a for a in self.addresses if a.current_address), None)


product_tags = db.Table(
    'product_tags',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)


###TODO unifiy the new logic for model and boxes
# class Product(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     price = db.Column(db.Float, nullable=False)
#
#     description = db.Column(db.Text)
#     image = db.Column(db.String(200))
#     weight = db.Column(db.Integer)
#     quantity = db.Column(db.Integer, default=0)
#     is_active = db.Column(db.Boolean, default=True)
#     comments = db.relationship('Comment', backref='product', lazy=True)
#     tags = db.relationship('Tag', secondary=product_tags, backref=db.backref('products', lazy='dynamic')
#                            , lazy='dynamic')
#     ############### this section contains data for the dynamic part
#     expiration_date = db.Column(db.DateTime, nullable=True)
#     date_added = db.Column(db.DateTime, default=func.now(), onupdate=func.now())
#     dynamic_pricing_enabled = db.Column(db.Boolean, default=False)
#     pending_price = db.Column(db.Float, nullable=True)  ##Price value for tomorrow or the next period of time
#     target_daily_sales = db.Column(db.Float, nullable=True)
#     sold_today = db.Column(db.Integer, default=0)
#     last_price_update = db.Column(db.DateTime, default=func.now())
#     floor_price = db.Column(db.Float, nullable=True)  ## min price that it cant drop below dynamically
#
#     ############### this section contains data for the dynamic part
#
#     embedding = db.Column(Vector(768))
#
#     def average_rating(self):
#         avg = db.session.query(func.avg(Comment.rating)) \
#             .filter(Comment.product_id == self.id).scalar()
#         return round(avg or 0, 1)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(200))
    pdf_image = db.Column(db.String(200), nullable=True)
    weight_per_unit = db.Column(db.Float, nullable=False)  # per unit weight
    is_active = db.Column(db.Boolean, default=True)

    ingredients = db.Column(db.Text, nullable=True)
    allergens = db.Column(db.JSON, nullable=True)

    # Nutrition fields
    energy_kj = db.Column(db.Float, nullable=True)
    energy_kcal = db.Column(db.Float, nullable=True)
    fat_g = db.Column(db.Float, nullable=True)
    saturates_g = db.Column(db.Float, nullable=True)
    carbs_g = db.Column(db.Float, nullable=True)
    sugars_g = db.Column(db.Float, nullable=True)
    fibre_g = db.Column(db.Float, nullable=True)
    protein_g = db.Column(db.Float, nullable=True)
    salt_g = db.Column(db.Float, nullable=True)

    # Relationships
    boxes = db.relationship('Box', back_populates='product', cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='product', lazy=True)
    tags = db.relationship(
        'Tag', secondary='product_tags',
        backref=db.backref('products', lazy='dynamic'), lazy='dynamic'
    )

    embedding = db.Column(Vector(768))  # if you still need embeddings

    def average_rating(self):
        avg = db.session.query(func.avg(Comment.rating)) \
            .filter(Comment.product_id == self.id).scalar()
        return round(avg or 0, 1)

    def update_active_status(self):
        """Sync product active status based on its boxes."""
        self.is_active = any(box.active for box in self.boxes)

    def lowest_price_box(self):
        # Only consider boxes that are active AND whose shipment has arrived
        arrived_and_active = [
            b for b in self.boxes
            if b.shipment.has_arrived and b.is_active
        ]

        if not arrived_and_active:
            return None

        return min(arrived_and_active, key=lambda b: b.price_inr_unit)


# Box model (per-lot / per-box of a product)
class Box(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product = db.relationship('Product', back_populates='boxes')

    shipment_id = db.Column(db.Integer, db.ForeignKey('shipment.id'))
    shipment = db.relationship('Shipment', back_populates='boxes')

    quantity = db.Column(db.Integer, nullable=False, default=1)
    weight_per_unit = db.Column(db.Float, nullable=False)
    expiration_date = db.Column(db.Date, nullable=True)
    date_added = db.Column(db.DateTime, default=func.now())

    # Prices in GBP (incoming cost side)
    price_gbp_unit = db.Column(db.Float, nullable=True) # previously na
    floor_price_gbp_unit = db.Column(db.Float, nullable=True) # previously floor_price_gbp
    landing_price_gbp_box = db.Column(db.Float, nullable=True)  # previously uk_price_at_shipment, landing_price_gbp



    # Prices in INR (customer side)
    price_inr_unit = db.Column(db.Float, nullable=True)  # previously price, price_inr
    floor_price_inr_unit = db.Column(db.Float, nullable=True)  # previously floor_price, floor_price_inr_unit
    landing_price_inr_box = db.Column(db.Float, nullable=True)  # previously na

    # Dynamic pricing
    dynamic_pricing_enabled = db.Column(db.Boolean, default=False)
    pending_price = db.Column(db.Float, nullable=True)
    target_daily_sales = db.Column(db.Float, nullable=True)
    sold_today = db.Column(db.Integer, default=0)
    last_price_update = db.Column(db.DateTime, default=func.now())

    is_active = db.Column(db.Boolean, default=True)

    @property
    def total_price_gbp(self):
        return self.landing_price_gbp_box

    @property
    def total_price_inr(self):
        return self.landing_price_inr_box

    @property
    def total_weight(self):
        return self.quantity * self.weight_per_unit


# Shipment model (container for boxes)
class Shipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Costs
    transit_cost = db.Column(db.Float, nullable=False, default=0.0)  # Cost when leaving UK
    tariff_cost_rupees = db.Column(db.Float, nullable=False, default=0.0)  # Actual cost in INR
    tariff_cost_gbp = db.Column(db.Float, nullable=True, default=0.0)  # Converted cost at landing

    # Status
    has_arrived = db.Column(db.Boolean, default=False)  # True once shipment has arrived
    date_arrived = db.Column(db.DateTime, nullable=True)
    inr_to_gbp_exchange_rate = db.Column(db.Float, nullable=False, default=0.0) #True value at time of landing
    boxes = db.relationship('Box', back_populates='shipment', cascade="all, delete-orphan")

    @property
    def total_product_cost(self):
        return sum(box.total_price_gbp for box in self.boxes)

    @property
    def total_weight(self):
        return sum(box.total_weight for box in self.boxes)

    @property
    def total_cost(self):
        return self.total_product_cost + self.transit_cost + self.tariff_cost_gbp

    @property
    def profitability(self):
        """
        Calculate the total profit for this shipment based on boxes' sales history.
        Profit = sum(sold_quantity * sold_price) - sum(sold_quantity * floor_price_inr_unit)
        """
        total_revenue = 0


        for box in self.boxes:
            for sale in box.sales_history:
                # Only consider sales from this shipment
                if sale.box.shipment_id == self.id:
                    total_revenue += (sale.sold_quantity * sale.sold_price)* self.inr_to_gbp_exchange_rate


        return total_revenue - self.total_cost


from datetime import datetime


############### this section contains data for the dynamic part
class BoxSalesHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    box_id = db.Column(db.Integer, db.ForeignKey('box.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    sold_quantity = db.Column(db.Integer, default=0)
    sold_price = db.Column(db.Float, nullable=False)  # price per unit sold
    target_daily_sales = db.Column(db.Float, nullable=False)
    demand = db.Column(db.Float, nullable=False)
    floor_price = db.Column(db.Float, nullable=False)

    box = db.relationship('Box', backref=db.backref('sales_history', lazy='select'))


############### this section contains data for the dynamic part

class PriceAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    target_price = db.Column(db.Float, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    notified = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='price_alerts')
    product = db.relationship('Product')

    def __init__(self, **kwargs):
        expires_at = kwargs.get('expires_at')
        if not expires_at:
            kwargs['expires_at'] = datetime.utcnow() + timedelta(days=30)
        super().__init__(**kwargs)


class SiteVisitCount(db.Model):
    date = db.Column(db.Date, primary_key=True)
    visit_count = db.Column(db.Integer, default=0)


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String, nullable=False)
    arg1 = db.Column(db.String)
    arg2 = db.Column(db.String)
    arg3 = db.Column(db.String)
    status = db.Column(db.String, default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    class TaskStatus:
        PENDING = "pending"
        IN_PROGRESS = "in-progress"
        DONE = "done"

    # optional helper
    def set_status(self, status):
        self.status = status


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
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=func.now())


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(20), db.ForeignKey('orders.order_id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    box_id = db.Column(db.Integer, db.ForeignKey('box.id'))  # new
    shipment_id = db.Column(db.Integer, db.ForeignKey('shipment.id'))  # new
    quantity = db.Column(db.Integer, default=1)
    price_at_purchase = db.Column(db.Float)  # box-specific price

    # Relationships
    product = db.relationship('Product', backref='order_items')
    box = db.relationship('Box')  # optional, for easy access
    shipment = db.relationship('Shipment')  # optional
    order = db.relationship('Orders', backref='order_items')


from sqlalchemy import event


@event.listens_for(Box, 'before_update')
def update_box_active(mapper, connection, target):
    """Keep box.active in sync with quantity."""
    if target.quantity <= 0 and target.is_active:
        target.is_active = False
    elif target.quantity > 0 and not target.is_active:
        target.is_active = True


@event.listens_for(Box, 'after_update')
@event.listens_for(Box, 'after_insert')
def sync_product_is_active(mapper, connection, target):
    """Update product.is_active after a box is updated or added."""
    product = target.product  # <-- this is the Box's related Product
    if not product:
        return

    # Determine if any boxes under this product are active
    product.is_active = any(box.is_active for box in product.boxes)

    # Directly update the product in the database
    connection.execute(
        Product.__table__.update()
        .where(Product.id == product.id)
        .values(is_active=product.is_active)
    )
