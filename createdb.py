import sqlite3
import hashlib
import random
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import BlindSig as bs
import cryptomath
import os
import base64

# Create a new SQLite database (or connect to an existing one)
conn = sqlite3.connect('evoting.db')
c = conn.cursor()

# Drop the keys table if it exists
c.execute("DROP TABLE IF EXISTS keys")

# Create tables
c.execute('''CREATE TABLE keys (
                id INTEGER PRIMARY KEY,
                n TEXT,
                e TEXT,
                d TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                name TEXT,
                photo TEXT,
                class TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS voters (
                id INTEGER PRIMARY KEY,
                id_number TEXT,
                digital_signature TEXT,
                approved INTEGER DEFAULT 0,
                photo TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS ballots (
                id INTEGER PRIMARY KEY,
                x TEXT,
                concatenated_message TEXT,
                message_hash TEXT,
                blinded_message TEXT,
                signed_blind_message TEXT,
                unblinded_signature TEXT)''')

conn.commit()

def get_db_connection():
    conn = sqlite3.connect('evoting.db')
    conn.row_factory = sqlite3.Row
    return conn

def save_keys(n, e, d):
    conn = get_db_connection()
    c = conn.cursor()
    params = (str(n), str(e), str(d))
    c.execute("INSERT INTO keys (n, e, d, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", params)
    conn.commit()
    conn.close()

def save_voter(id_number, digital_signature, photo_filename):
    conn = get_db_connection()
    c = conn.cursor()
    params = (id_number, digital_signature, photo_filename)
    c.execute("INSERT INTO voters (id_number, digital_signature, photo) VALUES (?, ?, ?)", params)
    conn.commit()
    conn.close()
    print(f"Saved voter: {id_number}")

def save_candidate(name, photo_filename, candidate_class):
    conn = get_db_connection()
    c = conn.cursor()
    params = (name, photo_filename, candidate_class)
    c.execute("INSERT INTO candidates (name, photo, class) VALUES (?, ?, ?)", params)
    conn.commit()
    conn.close()
    print(f"Saved candidate: {name}")

def save_ballot(x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature):
    conn = get_db_connection()
    c = conn.cursor()
    params = (str(x), concatenated_message, str(message_hash), str(blinded_message), str(signed_blind_message), str(unblinded_signature))
    c.execute('''INSERT INTO ballots (x, concatenated_message, message_hash, blinded_message, signed_blind_message, unblinded_signature)
                 VALUES (?, ?, ?, ?, ?, ?)''', params)
    conn.commit()
    conn.close()

def verify_ballot(id_number, public_key, n):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT digital_signature FROM voters WHERE id_number=?", (id_number,))
    voter = c.fetchone()
    conn.close()
    if voter:
        digital_signature = voter[0]
        decrypted_message = pow(int(digital_signature), public_key, n)
        if decrypted_message == int(id_number):
            print("Vote is valid")
        else:
            print("Vote is invalid")
    else:
        print("Voter not found")

def create_admin():
    conn = get_db_connection()
    c = conn.cursor()
    username = 'AdminKitaBersama'
    password = hashlib.sha256('AdminKitaBersama'.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

# Create admin user
create_admin()

def get_existing_keys():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()
    conn.close()
    if key:
        n, e, d = int(key[0]), int(key[1]), int(key[2])
        return n, e, d
    else:
        return None

def generate_and_save_keys():
    p = cryptomath.find_prime()
    q = cryptomath.find_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = cryptomath.find_mod_inverse(e, phi)
    save_keys(n, e, d)
    print("Keys generated and saved")

# Generate and save keys if they don't exist
if not get_existing_keys():
    generate_and_save_keys()