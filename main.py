from datetime import date
from typing import List

from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm
from forms import RegisterForm
from forms import LoginForm
from forms import CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)
login = LoginManager()
login.init_app(app)


# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user: Mapped["Users"] = relationship(back_populates="blog")
    comment: Mapped[List["Comment"]] = relationship(back_populates="blog")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text(), nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


# TODO: Create a User table for all your registered users.
class Users(db.Model, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blog: Mapped[List["BlogPost"]] = relationship(back_populates="user")
    comment: Mapped[List["Comment"]] = relationship(back_populates="user")
    email: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user: Mapped["Users"] = relationship(back_populates="comment")
    blog_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    blog: Mapped["BlogPost"] = relationship(back_populates="comment")


with app.app_context():
    db.create_all()


@login.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'Get'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        check = db.session.execute(db.select(Users).where(Users.email == form.email.data)).scalar()
        if check:
            flash("Email already exist please login")
            return redirect(url_for('login'))
        else:
            password = generate_password_hash(form.password.data, salt_length=8, method='pbkdf2')
            new_user = Users(password=password,
                             name=form.name.data,
                             email=form.email.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST', 'GET'])
def login():
    global admin
    form = LoginForm()
    if request.method == 'POST':
        email = db.session.execute(db.select(Users).where(Users.email == form.email.data)).scalar()
        if email.id == 1:
            admin = True
        if form.validate_on_submit():
            if email:
                if check_password_hash(password=form.password.data, pwhash=email.password):
                    login_user(email)
                    return redirect(url_for('get_all_posts'))
                else:
                    flash("Wrong Password! Please check your password")
                    return redirect(url_for('login'))
            else:
                flash("Wrong Email! Please check your email.")
                return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    global admin
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, auth=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "Get"])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        new = Comment(text=form.body.data,
                      user_id=current_user.id,
                      blog_id=post_id)
        db.session.add(new)
        db.session.commit()
        return redirect(url_for('show_post',post_id=post_id))

    return render_template("post.html", post=requested_post, auth=current_user.is_authenticated, form=form)


# TODO: Use a decorator so only an admin user can create a new post
def decorator(function):
    @wraps(function)
    def wrapped_function(*args, **kwargs):
        if current_user is not None:
            if current_user.id == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)

    return wrapped_function


@app.route("/new-post", methods=["GET", "POST"])
@decorator
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            user_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, auth=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@decorator
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, auth=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a pos
@app.route("/delete/<int:post_id>")
@decorator
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
