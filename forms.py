from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DecimalField, IntegerField, TextAreaField, DateField, \
    EmailField
from wtforms.validators import DataRequired, URL, NumberRange, EqualTo, Email
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
    price = DecimalField('Price', validators=[DataRequired()])
    description = TextAreaField('Description')
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    weight = DecimalField('Weight', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    tags = StringField('Tags')
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