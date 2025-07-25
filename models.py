import datetime
from flask_login import UserMixin
from sqlalchemy.sql import func
from extension import db
from datetime import datetime, timezone

product_tags = db.Table(
    'product_tags',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
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
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
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
    ############### this section contains data for the dynamic part
    expiration_date = db.Column(db.DateTime, nullable=True)
    date_added = db.Column(db.DateTime, default=func.now(), onupdate=func.now())
    dynamic_pricing_enabled = db.Column(db.Boolean, default=False)
    pending_price = db.Column(db.Float, nullable=True) ##Price value for tomorrow or the next period of time
    target_daily_sales = db.Column(db.Float, nullable=True)
    sold_today = db.Column(db.Integer, default=0)
    last_price_update = db.Column(db.DateTime, default=func.now())
    floor_price = db.Column(db.Float, nullable = True) ## min price that it cant drop below dynamically

    ############### this section contains data for the dynamic part

    def average_rating(self):
        avg = db.session.query(func.avg(Comment.rating)) \
            .filter(Comment.product_id == self.id).scalar()
        return round(avg or 0, 1)

############### this section contains data for the dynamic part
class ProductSalesHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    sold_quantity = db.Column(db.Integer, default=0)
    sold_price = db.Column(db.Float, nullable=False)  # price per unit sold
    target_daily_sales = db.Column(db.Float, nullable = False)
    demand = db.Column(db.Float, nullable = False)

    product = db.relationship('Product', backref=db.backref('sales_history', lazy='dynamic'))
############### this section contains data for the dynamic part

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
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    rating = db.Column(db.Integer, nullable=True)