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
    # Check if all characters are alphanumeric (or underscores) and if at least one character is alphabetical
    if all([c.isalnum() or c == '_' for c in username]) and any([c.isalpha() for c in username]):
        return True
    return False


def make_table(uid):
    '''Makes a GPA table in the database for a user'''
    # Make the table and index for the class names
    conn = sqlite3.connect('gpa.db')
    c = conn.cursor()
    c.execute('CREATE TABLE gpa_'+uid+' (name TEXT NOT NULL, grade TEXT NOT NULL, qp NUMERIC NOT NULL, bump NUMERIC DEFAULT 0 NOT NULL, credits DEFAULT 1 NOT NULL, wqp NUMERIC NOT NULL);')
    c.execute('CREATE INDEX gpa_classname'+uid+' ON gpa_'+uid+'("name");')
    conn.commit()
    conn.close()


# Below is Flask stuff. Comment it out if you want to try something without the HTML.

# Allows me to require the user to be logged in
def login_required(f):
    '''
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    '''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect('/login')
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


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        # Table for converting grades to quality points
        qptable = {'A+': 4.3, 'A': 4.0, 'A-': 3.7, 'B+': 3.3, 'B': 3.0, 'B-': 2.7,
                   'C+': 2.3, 'C': 2.0, 'C-': 1.7, 'D+': 1.3, 'D': 1.0, 'D-': 0.7, 'F': 0.0}
        # Get most of the data
        data = {'class_name': request.form.get('classname'), 'grade': request.form.get('grade'),
                'bump': float(request.form.get('bump')), 'credits': float(request.form.get('credits'))}
        # Get quality points
        data['qp'] = qptable[data['grade']] * data['credits']

        # Get weighted quality points
        # TODO: figure out if gpa bump is affected by credit multiplier
        if data['qp'] != 0:
            data['weightedqp'] = data['qp'] + data['bump']
        else:
            data['weightedqp'] = 0


        # Put data in database
        conn = sqlite3.connect('gpa.db')
        c = conn.cursor()
        c.execute('INSERT INTO gpa_'+str(session['user_id'])+' VALUES (?, ?, ?, ?, ?, ?);',
                  (data['class_name'], data['grade'], data['qp'], data['bump'], data['credits'], data['weightedqp']))
        conn.commit()
        conn.close()
        return redirect('/')
    else:
        conn = sqlite3.connect('gpa.db')
        c = conn.cursor()
        data = [i for i in c.execute(f'SELECT * FROM gpa_{str(session["user_id"])} ORDER BY name;')]
        conn.close()

        return render_template('index.html', data=data)


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


# Delete a class
@app.route('/remove', methods=['GET', 'POST'])
@login_required
def remove():
    if request.method == 'POST':
        conn = sqlite3.connect('gpa.db')
        c = conn.cursor()

        # Delete the class
        c.execute('DELETE FROM gpa_'+str(session['user_id'])+' WHERE name=?', (request.form.get('classname'),))
        conn.commit()

        conn.close()
        return redirect('/')
    else:
        # Get list of classes
        conn = sqlite3.connect('gpa.db')
        c = conn.cursor()
        classes = [i[0] for i in c.execute('SELECT name FROM gpa_'+str(session['user_id'])+' ORDER BY name')]
        conn.close()

        # Ensure user has classes to delete
        if len(classes) == 0:
            return apology('No classes to remove')

        return render_template('/remove.html', classes=classes)


# Log out
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Register user'''
    if request.method == 'POST':
        # Ensure username was submitted
        if not request.form.get('username'):
            return apology('Must provide username')

        # Ensure password was submitted
        elif not request.form.get('password'):
            return apology('Must provide password')

        # Ensure confirmation and password are the same
        elif request.form.get('confirmation') != request.form.get('password'):
            return apology('Passwords must match')

        # Ensure password has 8 characters and a number
        elif not any([c for c in request.form.get('password') if c.isnumeric()]) or not any([c for c in request.form.get('password') if c.isalpha()]) or len(request.form.get('password')) < 8:
            return apology('Password must have at least 8 characters, a number, and a letter')

        # Ensure that username is good
        elif not check_uname(request.form.get('username')):
            return apology('Username must only contain alphanumeric characters or underscores. At least one character must be alphabetical.')


        conn = sqlite3.connect('gpa.db')
        c = conn.cursor()

        for i in c.execute('SELECT username FROM users;'):
            if i[0] == request.form.get('username'):
                conn.commit()
                conn.close()
                return apology('Username already exists.')

        password, salt = hash(request.form.get('password'))

        # Put user in the database
        c.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (request.form.get('username'), password, salt))
        # Log in
        session['user_id'] = [i for i in c.execute('SELECT id FROM users WHERE username = ?;', (request.form.get('username'),))][0]

        conn.commit()
        conn.close()

        # Make a GPA table for the user
        make_table(str(session['user_id'][0]))

        return redirect('/')
    else:
        return render_template('register.html')