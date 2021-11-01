# IMPORTS
from datetime import datetime

import logging

from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import current_user, login_user, logout_user, login_required

from werkzeug.security import check_password_hash

from users.forms import RegisterForm, LoginForm

from models import User

from app import db, requires_roles

import pyotp

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_anonymous:
        # create signup form object
        form = RegisterForm()

        # if request method is POST or form is valid
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            # if this returns a user, then the email already exists in database

            # if email already exists redirect user back to signup page with error message so user can try again
            if user:
                flash('Email address already exists')
                return render_template('register.html', form=form)

            # create a new user with the form data
            new_user = User(email=form.email.data,
                            firstname=form.firstname.data,
                            lastname=form.lastname.data,
                            phone=form.phone.data,
                            password=form.password.data,
                            pin_key=form.pin_key.data,
                            role='user')

            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()

            logging.warning('SECURITY - User registration [%s, %s]', form.email.data, request.remote_addr)

            # sends user to login page
            return redirect(url_for('users.login'))
        # if request method is GET or form not valid re-render signup page
        return render_template('register.html', form=form)
    else:
        return render_template('403.html')


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_anonymous:
        # if session attribute logins does not exist create attribute logins
        if not session.get('logins'):
            session['logins'] = 0
        # if login attempts is 3 or more create an error message
        elif session.get('logins') >= 3:
            flash('Number of incorrect logins exceeded')

        form = LoginForm()

        if form.validate_on_submit():
            # increase login attempts by 1
            session['logins'] += 1

            # get user whose email matches the one entered
            user = User.query.filter_by(email=form.email.data).first()

            # if a user with that email exists and the password and OTP are correct, login user and update database
            if user and check_password_hash(user.password, form.password.data) \
                    and pyotp.TOTP(user.pin_key).verify(form.pin.data):

                # if user is verified reset login attempts to 0
                session['logins'] = 0

                login_user(user)

                user.last_logged_in = user.current_logged_in
                user.current_logged_in = datetime.now()
                db.session.add(user)
                db.session.commit()

                # log user login
                logging.warning('SECURITY - Log in [%s, %s, %s]', current_user.id, current_user.email,
                                request.remote_addr)

                # direct to role appropriate page
                if current_user.role == 'admin':
                    return redirect(url_for('admin.admin'))
                else:
                    return redirect(url_for('users.profile'))

            else:
                # log invalid login attempt
                logging.warning('SECURITY - Invalid login attempt [%s, %s]', form.email.data, request.remote_addr)

                # check number of invalid login attempts
                if session['logins'] == 3:
                    flash('Number of incorrect logins exceeded')
                elif session['logins'] == 2:
                    flash('Please check your login details and try again. 1 login attempt remaining')
                else:
                    flash('Please check your login details and try again. 2 login attempts remaining')

        return render_template('login.html', form=form)
    else:
        return render_template('403.html')


# user logout
@users_blueprint.route('/logout')
@login_required
def logout():
    # log user logout
    logging.warning('SECURITY - Log out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)

    logout_user()
    return redirect(url_for('index'))


# view user profile
@users_blueprint.route('/profile')
@requires_roles('user')
def profile():
    return render_template('profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@requires_roles('user', 'admin')
def account():
    return render_template('account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)
