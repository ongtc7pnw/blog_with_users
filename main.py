from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUserForm, LoginUserForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
#  $env:SECRET_KEY = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
# dir env:
secret_key = os.environ.get('SECRET_KEY')
print(secret_key)
print(type(secret_key))

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')   # '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


##CONNECT TO DB
database_url = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
if database_url.find('postgres://') == 0:
    database_url = database_url.replace('postgres://','postgresql://',1)
app.config['SQLALCHEMY_DATABASE_URI'] =  database_url    # os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None)


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(1000), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    #This will act like a List of BlogPost objects attached to each User.
    #The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    #The "author" refers to the author property in the Comment class.
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # relationship() = 'User' refers to class User, 'posts' refers to posts property in User class
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)


# db.create_all()


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user and current_user.get_id() == '1':
            pass
        else:
            return abort(403)
        return func(*args, **kwargs)
    return wrapper


@app.route('/')
def get_all_posts():
    admin = False
    if current_user and current_user.get_id() == '1':
        admin = True
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, is_admin=admin)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterUserForm()
    if register_form.validate_on_submit():
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        password = generate_password_hash(password)
        users = db.session.query(User).filter_by(email=email).all()
        if users:
            return redirect(url_for('login', email=email))
        else:
            user = User(
                name = name,
                email = email,
                password = password
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginUserForm()
    if login_form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password incorrect, please try again.")
        else:
            flash("Email does not exist, please try again.")
    else:
        email = request.args.get('email')
        if email:
            login_form = LoginUserForm(email=email)
            flash("You already signed up with that email, please log in instead.")
            login_form.email = email
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    admin = False
    if current_user and current_user.get_id() == '1':
        admin = True
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))

        comment = Comment(
            author_id=int(current_user.get_id()),
            post_id = requested_post.id,
            text = comment_form.comment_text.data,
            date = date.today().strftime("%B %d, %Y")
        )
        db.session.add(comment)
        db.session.commit()
        comment_form.comment_text.data = ""
    comments = db.session.query(Comment).filter_by(post_id=requested_post.id).all()
    return render_template("post.html", post=requested_post, is_admin=admin, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    mk_post_form = CreatePostForm()
    if mk_post_form.validate_on_submit():
        new_post = BlogPost(
            title=mk_post_form.title.data,
            subtitle=mk_post_form.subtitle.data,
            body=mk_post_form.body.data,
            img_url=mk_post_form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=mk_post_form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
    # app.run()
