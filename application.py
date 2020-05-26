#!/usr/bin/env python3

import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from functools import wraps
from hashlib import pbkdf2_hmac
from tempfile import mkdtemp


def hash(password):
    '''Return the hash of a password and its salt'''
    salt = os.urandom(32)
    return (pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 832379), salt)


def check_pass(username, password):
    '''Check if the password a user entered is correct.'''
    # Connect to the database
    conn = sqlite3.connect('gpa.db')
    c = conn.cursor()
    # Get the user's hashed password and their salt
    key, salt = [i for i in c.execute('SELECT password, salt FROM users WHERE username=?;', (username,))][0]
    new_key = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 832379)
    conn.close()

    # If the password matches, return True. Otherwise, return False.
    if new_key == key:
        return True
    return False


def check_uname(username):
    '''Makes sure the username won't cause a SQLi attack'''
    # Check if all characters are alphanumeric (or underscores) and is at least 6 characters long.
    # Also checks if at least one character is alphabetical
    if all([c.isalnum() or c == '_' for c in username]) \
    and len(username) >= 6 and any([c.isalpha() for c in username]):
        return True
    return False


# Consider changing the below function to also add a user into the users table
def make_table(username):
    '''Makes a GPA table in the database for a user'''
    # Double-check username
    if not check_uname(username):
        raise Exception('Username '+username+' isn\'t valid.')

    # Make the table and index for the class names
    conn = sqlite3.connect('gpa.db')
    c = conn.cursor()
    c.execute('CREATE TABLE gpa_'+username+' (name TEXT NOT NULL, grade TEXT NOT NULL, bump NUMERIC DEFAULT 0, credits DEFAULT 1 NOT NULL);')
    c.execute('CREATE INDEX gpa_classname'+username+' ON gpa_'+username+'("name");')
    conn.commit()
    conn.close()


# Below is Flask stuff. Comment it out if you want to try something without the HTML.

# This function allows me to require the user to be logged in
def login_required(f):
    '''
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    '''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# No idea what any of this does
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Configure session to use filesystem (instead of signed cookies)
app.config['SESSION_FILE_DIR'] = mkdtemp()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)


# Ensure that responses aren't cached
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/')
def index():
    return render_template('index.html')