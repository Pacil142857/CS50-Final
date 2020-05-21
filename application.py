#!/usr/bin/env python3

import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
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


