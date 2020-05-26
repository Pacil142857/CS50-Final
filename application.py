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
    new_key = pbkdf2_hmac('sha256', password, salt, 832379)
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


"""# testing delete this comment later
conn = sqlite3.connect('gpa.db')
c = conn.cursor()
x = hash('gamer1')
c.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', ('admin1', x[0], x[1]))
conn.commit()
conn.close()
"""
# Below is Flask stuff. Comment it out if you want to try something without the HTML.

# Allows me to require the user to be logged in
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


# Returns a page with an error message
def apology(message, code=400):
    '''Render message as an apology to user.'''
    return render_template('apology.html', top=code, bottom=message), code


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
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Log user in'''

    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':

        # Ensure username was submitted
        if not request.form.get('username'):
            return apology('Must provide username')

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password")

        conn = sqlite3.connect('gpa.db')
        c = conn.cursor()

        # Query database for username
        data = c.execute('SELECT * FROM users WHERE username = ?', (request.form.get('username'),))

        # Get the data by itself
        for i in data:
            data = i

        if type(data) == sqlite3.Cursor:
            conn.close()
            return apology('Invalid username and/or password')

        # Ensure username exists and password is correct
        if not check_pass(data[1], request.form.get('password').encode('utf-8')):
            conn.close()
            return apology('Invalid username and/or password')

        # Forget any user_id
        session.clear()

        # Remember which user has logged in
        session['user_id'] = data[0]

        conn.close()
        # Redirect user to home page
        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('login.html')

