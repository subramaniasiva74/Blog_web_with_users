from flask import Flask, render_template, redirect, url_for, flash, request, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                )


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "user_table"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user_table.id"))
    comments = relationship('Comment', back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = relationship('User', back_populates='comments')
    author_id = db.Column(db.Integer, db.ForeignKey("user_table.id"))
    parent_post = relationship('BlogPost', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


# db.create_all()

# db.session.query(User).delete()
# db.session.commit()

# new_user = db.session.query(User).get(1)
#
# new_post = BlogPost(
#     title="The Life of Cactus",
#     subtitle="Who knew that cacti lived such interesting lives.",
#     date="October 20, 2020",
#     body="<p>Nori grape silver beet broccoli kombu beet greens fava bean potato quandong celery.</p>"
#          "<p>Bunya nuts black-eyed pea prairie turnip leek lentil turnip greens parsnip.</p>"
#          "<p>Sea lettuce lettuce water chestnut eggplant winter purslane fennel azuki bean earthnut pea sierra leone bologi leek soko chicory celtuce parsley j&iacute;cama salsify.</p>",
#     img_url="https://images.unsplash.com/photo-1530482054429-cc491f61333b?ixlib=rb-1.2.1&ixid=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=crop&w=1651&q=80",
#     author=new_user,
#     author_id=new_user.id
# )

# db.session.add(new_post)
# db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user_id = current_user.get_id()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, id=user_id)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        form = RegisterForm()
        return render_template("register.html", form=form)
    else:
        form = RegisterForm()
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            user_pwd = generate_password_hash(password=form.pwd.data, salt_length=8, method="pbkdf2:sha256")
            new_user = User(email=form.email.data, password=user_pwd, name=form.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Email id already exists. Pls try login.')
            return redirect(url_for('login'))


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        form = LoginForm()
        return render_template("login.html", form=form)
    else:
        form = LoginForm()
        user_email = form.email.data
        user = db.session.query(User).filter_by(email=user_email).first()
        if user is not None:
            if check_password_hash(password=form.pwd.data, pwhash=user.password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password is incorrect')
                return redirect(url_for('login'))
        else:
            flash('Email id not found')
            return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    if request.method == "GET":
        form = CommentForm()
        requested_post = BlogPost.query.get(post_id)
        comments = Comment.query.all()
        return render_template("post.html", post=requested_post, id=current_user.get_id(),
                               logged_in=current_user.is_authenticated, form=form, comments=comments, gravatar=gravatar)

    else:
        if current_user.is_authenticated:
            form = CommentForm()
            new_user = db.session.query(User).get(int(current_user.get_id()))
            cmt_post = BlogPost.query.get(post_id)
            new_cmt = Comment(
                text=form.cmt.data,
                author=new_user,
                author_id=new_user.id,
                parent_post=cmt_post,
                post_id=cmt_post.id
            )
            db.session.add(new_cmt)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('Please Login to post comments')
            return redirect(url_for('login'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    if request.method == "GET":
        if current_user.get_id() == "1":
            form = CreatePostForm()
            if form.validate_on_submit():
                new_post = BlogPost(
                    title=form.title.data,
                    subtitle=form.subtitle.data,
                    body=form.body.data,
                    img_url=form.img_url.data,
                    author=current_user,
                    date=date.today().strftime("%B %d, %Y")
                )
                db.session.add(new_post)
                db.session.commit()
                return redirect(url_for("get_all_posts"))
            return render_template("make-post.html", form=form)
        else:
            abort(403, description="Access to the requested resource is forbidden")
    else:
        form = CreatePostForm()
        new_user = db.session.query(User).get(int(current_user.get_id()))
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            date="October 20, 2020",
            body=form.body.data,
            img_url=form.img_url.data,
            author=new_user,
            author_id=new_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
