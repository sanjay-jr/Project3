from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
from uuid import uuid4
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

limiter = Limiter(app, key_func=get_remote_address)

ph = PasswordHasher()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True)
    date_registered = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    last_login = db.Column(db.TIMESTAMP)

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(255), nullable=False)
    request_timestamp = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='auth_logs')

def encrypt_private_key(private_key):
    key = os.getenv("NOT_MY_KEY").encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key.encode('utf-8'), None)
    return urlsafe_b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_private_key(encrypted_private_key):
    key = os.getenv("NOT_MY_KEY").encode('utf-8')
    encrypted_data = urlsafe_b64decode(encrypted_private_key.encode('utf-8'))
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_data.decode('utf-8')

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    # Generate a secure password using UUIDv4
    password = str(uuid4())

    # Hash the password using Argon2
    password_hash = ph.hash(password)

    # Save user details to the database
    new_user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'password': password}), 201

@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate_user():
    request_ip = request.remote_addr
    username = request.json.get('username')

    # Check user authentication and log the request
    # For simplicity, assume authentication is successful
    # Replace this with your actual authentication logic
    user = User.query.filter_by(username=username).first()

    # Log the authentication request
    log_entry = AuthLog(request_ip=request_ip, user=user)
    db.session.add(log_entry)
    db.session.commit()

    # Return authentication result
    return jsonify({'message': 'Authentication successful'}), 200

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
