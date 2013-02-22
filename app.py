import os, random, string, requests, json, re, time
import hashlib, requests, json, time, os, re, urllib
from urlparse import urlparse

from flask import Flask, session, request, redirect, url_for, render_template, jsonify, Response
app = Flask(__name__, static_url_path='')
Flask.secret_key = os.environ.get('FLASK_SESSION_KEY', os.environ.get('SECRET_KEY', 'test-key-please-ignore'))

PORT = int(os.environ.get('PORT', 5000))
if 'PORT' in os.environ:
	HOSTNAME = 'directory.olinapps.com'
	HOST = 'directory.olinapps.com'
else:
	HOSTNAME = 'localhost'
	HOST = 'localhost:5000'

# Mongo
# -----------

from pymongo import Connection, ASCENDING, DESCENDING
from bson.code import Code
from bson.objectid import ObjectId

if os.environ.has_key('MONGOLAB_URI'):
	mongodb_uri = os.environ['MONGOLAB_URI']
	db_name = 'heroku_app9884622'
else:
	mongodb_uri = "mongodb://localhost:27017/"
	db_name = 'olinapps-directory'

connection = Connection(mongodb_uri)
db = connection[db_name]

def get_session_name():
	email = get_session_email()
	if not email:
		return None
	user = db.users.find_one(dict(email=email))
	if user:
		return user['nickname'] or user['name']
	return email.split('@', 1)[0].replace('.', ' ').title()

def ensure_session_user():
	email = get_session_email()
	if not email:
		return None
	if not db.users.find_one(dict(email=email)):
		db.users.insert(dict(
			email=email,
			name=get_session_name(),
			nickname='',
			room='',
			avatar='',
			phone='',
			year=''
		))
	return db.users.find_one(dict(email=email))

USER_KEYS = ['name', 'nickname', 'room', 'year', 'phone', 'mail',
	'twitter', 'facebook', 'tumblr', 'skype', 'pinterest', 'lastfm', 'google',
	'preferredemail'];

def db_user_json(user):
	json = dict(id=str(user['_id']), email=user['email']);
	for key in USER_KEYS:
		json[key] = user.get(key, '')
	json['domain'] = user['email'].split('@', 1)[1]
	return json

# Routes
# ------

@app.route('/')
def directory():
	user = ensure_session_user()
	return render_template('directory.html',
		email=session.get('email', None),
		name=get_session_name(),
		user=db_user_json(ensure_session_user()),
		people=[db_user_json(user) for user in db.users.find().sort('name', 1)])

# API

@app.route('/api')
def route_api():
	return render_template('api.html')

@app.route('/api/me', methods=['GET', 'POST'])
def api_me():
	user = ensure_session_user()
	if request.method == 'POST':
		for key in USER_KEYS:
			if request.form.has_key(key):
				user[key] = request.form[key]
		db.users.update({"_id": user['_id']}, user)
		return redirect('/')

	return jsonify(**db_user_json(user))

@app.route('/api/people')
def api_people():
	return jsonify(people=[db_user_json(user) for user in db.users.find().sort('name', 1)])

# Authentication
# ----------------------

def load_session(sessionid):
	r = requests.get('http://olinapps.com/api/me', params={"sessionid": sessionid})
	if r.status_code == 200 and r.json and r.json.has_key('user'):
		session['sessionid'] = sessionid
		session['user'] = r.json['user']
		return True
	return False

def get_session_user():
	return session.get('user')

def get_session_email():
	userinfo = get_session_user()
	if not userinfo:
		return None
	return str(userinfo['id']) + '@' + str(userinfo['domain'])

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		# External login.
		if request.form.has_key('sessionid') and load_session(request.form.get('sessionid')):
			return redirect('/')
		else:
			session.pop('sessionid', None)
			return "Invalid session token: %s" % sessionid
	return "Please authenticate with Olin Apps to view Directory."

@app.route('/logout', methods=['GET', 'POST'])
def logout():
	session.pop('sessionid', None)
	session.pop('user', None)
	return redirect('/')

# All pages are accessible, but enable user accounts.
@app.before_request
def before_request():
	if urlparse(request.url).path == '/login':
		return
	if not get_session_user():
		if request.args.has_key('sessionid') and load_session(request.args.get('sessionid')):
			return
		if urlparse(request.url).path.startswith('/api/'):
			return Response(json.dumps({"error": "Not authorized"}), 401, {"Content-Type": "application/json"})
		return redirect('http://olinapps.com/external?callback=http://%s/login' % HOST)

@app.after_request
def after_request(response):
	if urlparse(request.url).path.startswith('/api/') and request.headers.get('Origin'):
		remotehost = urlparse(request.headers.get('Origin')).netloc
		if re.match(r'^localhost:[0-9]+$', remotehost) or re.match(r'^[^.]+\.olinapps\.com', remotehost):
				response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin'))
		response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin'))
		response.headers.add('Access-Control-Allow-Methods', 'POST, GET, PUT, PATCH, DELETE, OPTIONS')
		response.headers.add('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, Cookie')
		response.headers.add('Access-Control-Allow-Credentials', 'true')
		response.headers.add('Access-Control-Max-Age', '1728000')
	return response

# Launch
# ------

app.debug = True

if __name__ == '__main__':
	# Bind to PORT if defined, otherwise default to 5000.
	app.debug = True
	app.run(host=HOSTNAME, port=PORT)
