"""
Virtual Supervisor — Flask Backend
===================================
Routes
------
POST /api/auth/login        Verify Firebase ID token → set session
POST /api/auth/register     Create Firebase user + Firestore profile
POST /api/auth/logout       Clear session
GET  /api/auth/me           Return current user from session
GET  /dashboard             Serve dashboard (protected)
GET  /                      Serve login page

Setup
-----
1. pip install -r requirements.txt
2. Copy .env.example → .env and fill in values
3. Place serviceAccountKey.json in this folder (do NOT commit it)
4. python app.py
"""

import os
import json
from functools import wraps
from datetime import timedelta

from flask import (
	Flask, request, jsonify, session,
	redirect, url_for, send_from_directory
)
from flask_cors import CORS
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore

# ── Load environment variables ─────────────────────────────────────────────
load_dotenv()

# ── Flask app ──────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')

app.secret_key          = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production')
app.permanent_session_lifetime = timedelta(days=7)

CORS(app,
     supports_credentials=True,
     origins=["https://virtual-spervisor.web.app", "http://localhost:5000"])

# ── Firebase Admin SDK init ────────────────────────────────────────────────
_SERVICE_ACCOUNT_PATH = os.getenv('FIREBASE_SERVICE_ACCOUNT', 'serviceAccountKey.json')

if not firebase_admin._apps:
	if os.path.exists(_SERVICE_ACCOUNT_PATH):
		cred = credentials.Certificate(_SERVICE_ACCOUNT_PATH)
		firebase_admin.initialize_app(cred)
		print(f"[Firebase] Initialised from {_SERVICE_ACCOUNT_PATH}")
	else:
		# Fallback: read from environment variable (useful for deployment)
		service_account_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
		if service_account_json:
			cred = credentials.Certificate(json.loads(service_account_json))
			firebase_admin.initialize_app(cred)
			print("[Firebase] Initialised from environment variable")
		else:
			print("[Firebase] WARNING: No service account found. Auth will fail.")

db = firestore.client() if firebase_admin._apps else None


# ── Auth decorator ─────────────────────────────────────────────────────────
def login_required(f):
	"""Redirect to login if no valid session exists."""
	@wraps(f)
	def decorated(*args, **kwargs):
		if 'uid' not in session:
			if request.is_json:
				return jsonify({'error': 'Unauthorised'}), 401
			return redirect(url_for('serve_login'))
		return f(*args, **kwargs)
	return decorated


# ── Helpers ────────────────────────────────────────────────────────────────
def _verify_id_token(id_token: str):
	"""Verify a Firebase ID token and return the decoded payload."""
	try:
		return firebase_auth.verify_id_token(id_token)
	except firebase_auth.ExpiredIdTokenError:
		raise ValueError('Token has expired. Please sign in again.')
	except firebase_auth.InvalidIdTokenError:
		raise ValueError('Invalid token. Please sign in again.')
	except Exception as e:
		raise ValueError(f'Token verification failed: {str(e)}')


def _get_or_create_firestore_profile(uid: str, email: str, display_name: str):
	"""Get existing Firestore user doc or create one."""
	if db is None:
		return {'uid': uid, 'email': email, 'displayName': display_name}

	ref = db.collection('users').document(uid)
	doc = ref.get()

	if not doc.exists:
		profile = {
			'uid':         uid,
			'email':       email,
			'displayName': display_name,
			'role':        'employee',
			'createdAt':   firestore.SERVER_TIMESTAMP,
			'lastLogin':   firestore.SERVER_TIMESTAMP,
		}
		ref.set(profile)
		return profile

	# Update last login timestamp
	ref.update({'lastLogin': firestore.SERVER_TIMESTAMP})
	return doc.to_dict()


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES  (serve HTML files)
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def serve_login():
	"""Serve the login page. Redirect to dashboard if already logged in."""
	if 'uid' in session:
		return redirect(url_for('serve_dashboard'))
	return send_from_directory('templates', 'login.html')


@app.route('/dashboard')
@login_required
def serve_dashboard():
	"""Serve the main dashboard. Protected route."""
	return send_from_directory('templates', 'dashboard.html')


# ══════════════════════════════════════════════════════════════════════════════
#  API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
def api_login():
	"""
	Verify a Firebase ID token sent from the frontend after signInWithEmailAndPassword.

	Request body (JSON):
	    { "idToken": "<firebase-id-token>" }

	Response (JSON):
	    { "success": true, "user": { "uid", "email", "displayName" } }
	"""
	data = request.get_json(silent=True) or {}
	id_token = data.get('idToken', '').strip()

	if not id_token:
		return jsonify({'error': 'ID token is required'}), 400

	try:
		decoded = _verify_id_token(id_token)
	except ValueError as e:
		return jsonify({'error': str(e)}), 401

	uid          = decoded['uid']
	email        = decoded.get('email', '')
	display_name = decoded.get('name', email.split('@')[0].title())

	# Store user profile in Firestore
	profile = _get_or_create_firestore_profile(uid, email, display_name)

	# Persist server-side session
	session.permanent = True
	session['uid']          = uid
	session['email']        = email
	session['display_name'] = profile.get('displayName', display_name)
	session['role']         = profile.get('role', 'employee')

	return jsonify({
		'success': True,
		'user': {
			'uid':         uid,
			'email':       email,
			'displayName': session['display_name'],
			'role':        session['role'],
		}
	})


@app.route('/api/auth/register', methods=['POST'])
def api_register():
	"""
	Register a new user via Firebase Auth then store their profile in Firestore.

	Request body (JSON):
	    { "idToken": "<firebase-id-token>", "displayName": "John Doe" }

	The frontend should:
	1. Call Firebase createUserWithEmailAndPassword()
	2. Call Firebase updateProfile() to set displayName
	3. Get the idToken and POST it here with the displayName

	Response (JSON):
	    { "success": true, "user": { ... } }
	"""
	data = request.get_json(silent=True) or {}
	id_token     = data.get('idToken', '').strip()
	display_name = data.get('displayName', '').strip()

	if not id_token:
		return jsonify({'error': 'ID token is required'}), 400

	try:
		decoded = _verify_id_token(id_token)
	except ValueError as e:
		return jsonify({'error': str(e)}), 401

	uid   = decoded['uid']
	email = decoded.get('email', '')
	name  = display_name or decoded.get('name', email.split('@')[0].title())

	profile = _get_or_create_firestore_profile(uid, email, name)

	session.permanent = True
	session['uid']          = uid
	session['email']        = email
	session['display_name'] = name
	session['role']         = profile.get('role', 'employee')

	return jsonify({
		'success': True,
		'user': {
			'uid':         uid,
			'email':       email,
			'displayName': name,
			'role':        session['role'],
		}
	})


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
	"""Clear the server-side session."""
	session.clear()
	return jsonify({'success': True})


@app.route('/api/auth/me', methods=['GET'])
@login_required
def api_me():
	"""Return the currently logged-in user from session."""
	return jsonify({
		'uid':         session.get('uid'),
		'email':       session.get('email'),
		'displayName': session.get('display_name'),
		'role':        session.get('role'),
	})


# ── Health check ───────────────────────────────────────────────────────────
@app.route('/api/health')
def health():
	return jsonify({
		'status':   'ok',
		'firebase': bool(firebase_admin._apps),
		'db':       db is not None,
	})


# ── Run ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
	port  = int(os.getenv('PORT', 5000))
	debug = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'
	print(f"[Virtual Supervisor] Starting on http://localhost:{port}")
	app.run(host='0.0.0.0', port=port, debug=debug)