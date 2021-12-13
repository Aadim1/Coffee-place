from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from wtforms import StringField, SubmitField, SelectField, TimeField, PasswordField
from wtforms.validators import DataRequired, URL, InputRequired, ValidationError, Email, EqualTo
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_nav import Nav
from flask_sqlalchemy import SQLAlchemy
from flask_nav.elements import *
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
nav = Nav()
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///userdata.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Bootstrap(app)
bcrypt = Bcrypt(app=app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


def validate_email(form, email):
    if User.query.filter_by(email=email.data).first():
        raise ValidationError("You've already signed up using this email! Please log in")


def validate_signupusername(form, username):
    if User.query.filter_by(username=username.data).first():
        raise ValidationError("Username is already in use please select another one")


def validate(form, password):
    print("Validate Password: ", form.login_username.data)
    user = User.query.filter_by(username=form.login_username.data).first()
    if user:
        if check_password_hash(user.password, password=password.data):
            return True
        else:
            raise ValidationError("Username or Password incorrect please try again")
    else:
        raise ValidationError("Username or Password incorrect please try again")


class signupform(FlaskForm):
    signup_username = StringField('username', validators=[DataRequired(), validate_signupusername])
    email = StringField('Email', validators=[Email(), DataRequired(), validate_email])
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm_password', message="Password must match")])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit_button = SubmitField("Submit")


class LoginForm(FlaskForm):
    login_username = StringField('username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), validate])
    login_button = SubmitField("Log in")


class CafeForm(FlaskForm):
    cafe = StringField('Cafe name', validators=[DataRequired()])
    location = StringField('Location', validators=[URL(require_tld=True)])
    open = StringField('Opening Time Eg: 8 AM', validators=[])
    close = StringField('Closing Time Eg: 7:30 PM', validators=[])
    coffee = SelectField('Coffee Rating', choices=["☕", "☕☕", "☕☕☕", "☕☕☕☕", "☕☕☕☕☕"],
                         validators=[DataRequired()])
    wifi = SelectField('Wifi Strength Rating',
                       choices=["✘", "💪", "💪💪", "💪💪💪", "💪💪💪💪", "💪💪💪💪💪"],
                       validators=[DataRequired()])
    power = SelectField('Power Socket Availability',
                        choices=["✘", "🔌", "🔌🔌", "🔌🔌🔌", "🔌🔌🔌🔌", "🔌🔌🔌🔌🔌"],
                        validators=[DataRequired()])
    submit = SubmitField('Add')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    cafes = db.relationship('CafeData', backref="owner")


class CafeData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cafe_name = db.Column(db.String(1000), nullable=False)
    location = db.Column(db.String(10000000), nullable=False)
    open = db.Column(db.String(8), nullable=False)
    close = db.Column(db.String(8), nullable=False)
    coffee = db.Column(db.String(6), nullable=False)
    wi_fi = db.Column(db.String(6), nullable=False)
    power = db.Column(db.String(6), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


db.create_all()


def dosomething():
    print("It worked")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# all Flask routes below
@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("index.html", current_user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.login_username.data).first()
        if request.form.get("remember_me") is not None:
            login_user(user, remember=True)
        else:
            login_user(user)
        return redirect(url_for('cafes'))
    return render_template("login.html", dosomething=dosomething, form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = signupform()
    if form.validate_on_submit():
        print("Problem")
        username = form.signup_username.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("signup.html", form=form)


@app.route('/add', methods=["GET", "POST"])
def add_cafe():
    form = CafeForm()
    print(current_user.id)
    if form.validate_on_submit():
        cafe_data = CafeData(cafe_name=form.cafe.data,
                             location=form.location.data,
                             open=form.open.data,
                             close=form.close.data,
                             coffee=form.coffee.data,
                             wi_fi=form.wifi.data,
                             power=form.power.data,
                             owner=current_user)
        db.session.add(cafe_data)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add.html', form=form)


@app.route('/cafes')
@login_required
def cafes():
    """
    lists out all the added cafes in database in the good table format.
    :return: list of cafes in table format
    """
    data = CafeData.query.filter_by(owner_id=current_user.id).all()
    list_of_cafes = [["Cafe Name", "Location", "Open", "Close", "Coffee", "Wi Fi", "Power"],
                     [[key.cafe_name, key.location, key.open, key.close, key.coffee, key.wi_fi, key.power] for key in
                      data]]

    print(list_of_cafes)

    return render_template('cafes.html', cafes=list_of_cafes)


@app.route('/delete')
def delete():
    """
    deletes the details of the cafe
    :return:
    """
    print(request.args.get('cafe'))
    CafeData.query.filter_by(cafe_name=request.args.get('cafe')).delete()
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
