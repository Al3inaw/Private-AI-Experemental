import bcrypt
import jwt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from functools import wraps

SECRET_KEY = 'your-secret-key'  # In production, use a secure method to manage this key

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

class SecurityEnhancedAI(OneBillionAI):
    def __init__(self):
        super().__init__()
        self.failed_attempts = {}

    def authenticate(self, username, password):
        user = self.get_user(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            self.failed_attempts[username] = 0
            return self.generate_token(username)
        else:
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            if self.failed_attempts[username] >= 5:
                self.lock_account(username)
            return None

    def get_user(self, username):
        # In a real system, this would query a secure database
        return {'username': username, 'password': bcrypt.hashpw(b'Qwer@1234', bcrypt.gensalt())}

    def generate_token(self, username):
        expiration = datetime.utcnow() + timedelta(hours=1)
        return jwt.encode({'user': username, 'exp': expiration}, SECRET_KEY, algorithm="HS256")

    def lock_account(self, username):
        # In a real system, this would update a secure database
        print(f"Account {username} has been locked due to too many failed attempts.")

    @token_required
    def process_query(self, query):
        return super().process_query(query)

app = Flask(__name__)
ai_assistant = SecurityEnhancedAI()

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Could not verify'}), 401
    token = ai_assistant.authenticate(auth.username, auth.password)
    if not token:
        return jsonify({'message': 'Invalid credentials'}), 401
    return jsonify({'token': token})

# All other routes should use the @token_required decorator
