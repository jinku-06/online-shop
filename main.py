from flask import Flask, render_template, request, url_for, redirect, abort, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from flask_bootstrap import Bootstrap5
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
from form import UserForm, LoginForm, ProductsForm, Checkout
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    login_user,
    UserMixin,
    login_required,
    logout_user,
    current_user,
    login_manager,
)
import stripe
from functools import wraps
import os

load_dotenv()


YOUR_DOMAIN = "http://localhost:4242"
API = os.getenv("stripe_api")
PRICE = os.getenv("price")
stripe.api_key = API


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///shop.db"
db.init_app(app)
bootstrap = Bootstrap5(app)
csrf = CSRFProtect(app)
login_manager.init_app(app=app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    email: Mapped[str] = mapped_column(nullable=False)
    password: Mapped[str]
    is_admin: Mapped[bool] = mapped_column(nullable=False, default=False)


class Items(db.Model):
    __tablename__ = "items"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False)
    img_url: Mapped[str] = mapped_column(nullable=False)
    price: Mapped[int] = mapped_column(nullable=False)


with app.app_context():
    db.create_all()


@app.route("/shop")
@login_required
def home():
    form = Checkout()
    data = db.session.execute(db.select(Items)).scalars().all()
    return render_template("index.html", data=data, form=form)


@app.route("/")
def login_():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = UserForm()
    print(form.username.data)
    print(form.password.data)
    user = User.query.filter_by(username=form.username.data).first()
    is_email = User.query.filter_by(email=form.email.data)
    if form.validate_on_submit():
        if not user or not is_email:
            username = form.username.data
            email = form.email.data
            hash_password = generate_password_hash(
                password=form.password.data, method="pbkdf2:sha256", salt_length=9
            )
            is_admin = True if username == "admin@" else False
            new_user = User(
                username=username,
                email=email,
                password=hash_password,
                is_admin=is_admin,
            )

            db.session.add(new_user)
            db.session.commit()
            flash("Believe it! You're all set to login, shinobi!", "success")

            return redirect(url_for("login"))

        elif user:
            flash("That username's already taken, dattebayo! Pick a new one.", "danger")
            return redirect(url_for("register"))
        elif is_email:
            flash(
                "Oi, that email's already in use! Don't be like Naruto with his pranks.",
                "danger",
            )
            return redirect(url_for("register"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash("You're not in the ninja registry! Please register first.", "danger")
            return redirect("/login")
        elif not check_password_hash(user.password, form.password.data):
            flash(
                "Password mismatch! Naruto never got this far by giving up.", "danger"
            )
            return redirect("/login")
        else:
            login_user(user)
            flash(
                "Welcome back, shinobi! Time to conquer the village marketplace.",
                "success",
            )

            return redirect(url_for("home"))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash("You've logged out. Rest up, shinobi, more challenges await!", "info")

    return redirect(url_for("login"))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route("/new", methods=["GET", "POST"])
@admin_required
def add_product():
    form = ProductsForm()
    if form.validate_on_submit():
        name = form.name.data
        img_url = form.img_url.data
        price = form.price.data

        new_item = Items(name=name, img_url=img_url, price=price)
        db.session.add(new_item)
        db.session.commit()
        data = db.session.execute(db.select(Items)).scalars().all()
        return render_template("checkout.html", data=data)
    return render_template("add_product.html", form=form)


@app.route("/update/<int:id>", methods=["GET", "POST"])
@admin_required
def update(id):
    item = Items.query.get_or_404(id)
    form = ProductsForm(obj=item)
    form.add.label.text = "Update"
    if form.validate_on_submit():
        name = form.name.data
        img_url = form.img_url.data
        price = form.price.data

        item.name = name
        item.img_url = img_url
        item.price = price
        db.session.commit()

        flash("Item updated successfully", "success")
        return redirect(url_for("home"))
    return render_template("update.html", form=form)


@app.route("/delete/<int:id>")
@admin_required
def delete(id):
    item = Items.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash(f"Successfully deleted item with id: {id}", "success")
    return redirect(url_for("home"))


@app.route("/success")
def success():
    return render_template("success.html")


@app.route("/cancel")
def cancel():
    return render_template("cancel.html")


@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": PRICE,
                    "quantity": 1,
                },
            ],
            mode="payment",
            success_url=YOUR_DOMAIN + "/success",
            cancel_url=YOUR_DOMAIN + "/cancel",
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


if __name__ == "__main__":
    app.run(debug=True, port=4242)
