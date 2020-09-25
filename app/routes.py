# -*- coding: utf-8 -*-
from datetime import datetime
import requests

from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, PostForm
from app.models import User, Post
from .oauth import OAuthSignIn
from .utils import build_block, build_email


@app.route('/', methods=["GET", "POST"])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Ваш пост теперь существует!')
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    posts = current_user.followed_post().paginate(
        page, app.config["POST_PER_PAGE"], False
    )
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title='Home Page', form=form,
                           posts=posts.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        if "yandex_enter" in request.form:
            return redirect(url_for("oauth_authorize", provider="yandex"))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password")
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Вход', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Отлично! Теперь вы новый пользователь!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)


@app.route("/edit_profile", methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Ваши изменения были приняты')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form, title='Редактирование профиля')


@app.route("/user/<username>")
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = user.post.paginate(
        page, app.config["POST_PER_PAGE"], False
    )
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('user.html', user=user, posts=posts.items, next_url=next_url,
                           prev_url=prev_url)


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} is not found.'.format(username))
        return redirect(url_for('index'))

    if user == current_user:
        flash('You can not follow yourself!')
        return redirect(url_for('user', username=username))

    current_user.follow(user)
    db.session.commit()
    flash('You are follow user {}'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} is not found.'.format(username))
        return redirect(url_for('index'))

    if user == current_user:
        flash('You can not unfollow yourself!')
        return redirect(url_for('user', username=username))

    current_user.unfollow(user)
    db.session.commit()
    flash('You are not follow user {}'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config["POST_PER_PAGE"], False
    )
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title='Explore', posts=posts.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    social_id = oauth.callback()
    if social_id is None:
        flash('Authentication failed.')
        return redirect(url_for('index'))
    user = User.query.filter_by(social_id=social_id).first()
    if not user:
        headers = {"Authorization": "OAuth " + social_id}
        response = requests.get('https://login.yandex.ru/info?format=json', headers=headers)
        data_from_yandex = response.json()
        # Делать запрос для получения данных пользователя, получать их в виде json и писать в базу вместе с сгенерированным паролем
        user = User(social_id=social_id, username=data_from_yandex['login'], email=data_from_yandex['default_email'])
        db.session.add(user)
        db.session.commit()
        # return redirect(url_for('index'))
    login_user(user, True)
    return redirect(url_for('index'))
