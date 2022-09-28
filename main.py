from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, BooleanField, FloatField, PasswordField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditor

app = Flask(__name__)
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager =LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafe.db'
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), unique=True, nullable=False)
    has_wifi = db.Column(db.Boolean(6), nullable=False)
    has_electricity = db.Column(db.Boolean(6), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(150), nullable=False)


class NewCafe(FlaskForm):
    title = StringField("name of Cafe", validators=[DataRequired()])
    has_wifi = BooleanField("Does this place have wifi?", validators=[DataRequired()])
    has_electricity = BooleanField("does this place have plugs?", validators=[DataRequired()])
    rating = FloatField("Rating out of 5")
    address = StringField("where is the Cafe Situated?")
    submit = SubmitField("Add new Cafe to the List")

class RegisterForm(FlaskForm):
    email = StringField("email address", validators=[DataRequired()])
    name = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    signup = SubmitField("Sign me UP!")


class LoginForm(FlaskForm):
    name = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

@app.route('/')
def display_all():
    posts = Cafe.query.all()
    return render_template("index.html", all_posts=posts, current_user = current_user)

@app.route('/signup', methods=["GET", "POSt"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email = form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())# User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("display_all"))

    return render_template("signup.html", form=form, current_user=current_user)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.name.data
        password = form.password.data
        user = User.query.filter_by(name=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('display_all'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('display_all'))


@app.route("/create", methods=["GET", "POST"])
def post_new_cafe():
    form = NewCafe()
    if form.validate_on_submit():
        new_cafe = Cafe(
            title=form.title.data,
            has_wifi=form.has_wifi.data,
            has_electricity=form.has_electricity.data,
            rating=form.rating.data,
            address=form.address.data,
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("display_all"))
    return render_template("create.html", form=form)

@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = Cafe.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('display_all', post_to_delete = post_id))

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)

#only able to delete post if logged in