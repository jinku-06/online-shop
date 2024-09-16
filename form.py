from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, EmailField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Length


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(6, 50)])
    email = EmailField(label="Email", validators=[DataRequired()])
    password = PasswordField(
        label="Password", validators=[DataRequired(), Length(5, 50)]
    )
    register = SubmitField(label="Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    login = SubmitField(label="Login")


class ProductsForm(FlaskForm):
    name = StringField(label="Product Name", validators=[DataRequired()])
    price = IntegerField(label="Price", validators=[DataRequired()])
    img_url = StringField(label="Image Url", validators=[DataRequired()])
    add = SubmitField(label="Add", validators=[DataRequired()])


class Checkout(FlaskForm):
    buy = SubmitField("Checkout")
