from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DecimalField, IntegerField, TextAreaField, DateField, \
    EmailField, SelectField, BooleanField, HiddenField, FloatField
from wtforms.validators import DataRequired, NumberRange, EqualTo, Email, Optional
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField, FileAllowed


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(), EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField("Sign Me Up!")

class AddToCartForm(FlaskForm):
    product_id = HiddenField('Product ID', validators=[DataRequired()])
    box_id = HiddenField('Box ID', validators=[DataRequired()])
    shipment_id = HiddenField('Shipment ID', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Add to Cart')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()], render_kw={"autocomplete": "username"})
    password = PasswordField("Password", validators=[DataRequired()],render_kw={"autocomplete": "current-password"})
    submit = SubmitField("Let Me In!")

class AddAddress(FlaskForm):
    address = StringField("Street Address", validators=[DataRequired()])
    city = StringField("City", validators=[DataRequired()])
    postcode = StringField("Postcode", validators=[DataRequired()])
    submit = SubmitField("Add address")

##TODO fix the implentation of this properly Create_new_product
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'avif'])])
    weight_per_unit = DecimalField('Weight per Unit (g)', validators=[DataRequired()])
    tags = StringField('Tags', validators=[Optional()])

    ingredients = TextAreaField("Ingredients", validators=[Optional()])
    allergens = StringField("Allergens (comma-separated)", validators=[Optional()])

    # Nutrition
    energy_kj = FloatField("Energy (kJ)", validators=[Optional()])
    energy_kcal = FloatField("Energy (kcal)", validators=[Optional()])
    fat_g = FloatField("Fat (g)", validators=[Optional()])
    saturates_g = FloatField("Saturates (g)", validators=[Optional()])
    carbs_g = FloatField("Carbs (g)", validators=[Optional()])
    sugars_g = FloatField("Sugars (g)", validators=[Optional()])
    fibre_g = FloatField("Fibre (g)", validators=[Optional()])
    protein_g = FloatField("Protein (g)", validators=[Optional()])
    salt_g = FloatField("Salt (g)", validators=[Optional()])
    submit = SubmitField('Create Product')


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    rating = IntegerField('Rating', validators=[NumberRange(min=1, max=5)])
    submit = SubmitField("Submit Comment")

class StockForm(FlaskForm):
    quantity = IntegerField("Quantity", validators=[DataRequired()])
    expiry_date = DateField("Expiry Date", format="%Y-%m-%d", validators=[DataRequired()])
    floor_price = DecimalField("Price Floor", validators=[DataRequired()])
    submit = SubmitField("Add Stock")

class TrackingForm(FlaskForm):
    tracking_code = StringField('Tracking Code', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ShipmentSentForm(FlaskForm):
    transit_cost = DecimalField("Transit Cost (£)", validators=[DataRequired()])
    tariff_cost = DecimalField("Tariff Cost (₹)")
    submit = SubmitField("Create Shipment")

class ShipmentArrivalForm(FlaskForm):
    tariff_cost = DecimalField("Tariff Cost (₹)")
    submit = SubmitField("This Shipment has arrived.")

class BoxForm(FlaskForm):
    product_id = SelectField("Product", coerce=int, validators=[DataRequired()])
    quantity = IntegerField("Quantity", default=1, validators=[DataRequired(), NumberRange(min=1)])
    uk_price_at_shipment = DecimalField("UK Price at Shipment (£)", validators=[DataRequired(), NumberRange(min=0)])
    weight_per_unit = DecimalField("Weight per Unit (g)", validators=[DataRequired(), NumberRange(min=0)])
    expiration_date = DateField("Expiration Date", validators=[Optional()])
    dynamic_pricing_enabled = BooleanField("Enable Dynamic Pricing")
    submit = SubmitField("Add Box to Shipment")