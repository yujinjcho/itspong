from flask import render_template, url_for, session, request, redirect, jsonify, g
from flask_oauthlib.client import OAuthException
from geopy.geocoders import Nominatim
from geopy.distance import vincenty
from app import app, db, google, facebook
from models import User, GeoUserTest
from geocoder import distance

@app.route('/')
def index():	
	
	if g.user:
		return redirect(url_for('findGame'))
	return render_template('index.html')

def createUser(me, auth_server_name):  
	if auth_server_name == 'Facebook':
		profile_url = me.data['picture']['data']['url']
	else:
		profile_url = me.data['picture']
	new_user = User(auth_server=auth_server_name,	
  	auth_server_id=me.data['id'],
		name=me.data['name'],
		email=me.data['email'],
		profile_pic=profile_url)
	
	db.session.add(new_user)
	db.session.commit()

#Facebook Login
@app.route('/fb_login')
def fb_login():
	callback = url_for(
		'facebook_authorized',
		next=request.args.get('next') or request.referrer or None,
		_external=True
	)
	return facebook.authorize(callback=callback)

@app.route('/login/fb_authorized')
def facebook_authorized():
  resp = facebook.authorized_response()
  if resp is None:
      return 'Access denied: reason=%s error=%s' % (
          request.args['error_reason'],
          request.args['error_description']
      )
  if isinstance(resp, OAuthException):
      return 'Access denied: %s' % resp.message

  session['oauth_token'] = (resp['access_token'], '')
  me = facebook.get('/me/?fields=email,picture,name,id')
  user = User.query.filter_by(auth_server='Facebook',auth_server_id=me.data['id']).first()
  
  if user is None:
    createUser(me, 'Facebook')
    user = User.query.filter_by(auth_server='Facebook',auth_server_id=me.data['id']).first()
    session['user_id'] = user.id
    g.user = user.id
    return redirect(url_for('set_location'))
  
  session['user_id'] = user.id
  return redirect(url_for('findGame'))

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')

#Google Login
@app.route('/login/g_authorized')
def g_authorized():
  resp = google.authorized_response()
  if resp is None:
      return 'Access denied: reason=%s error=%s' % (
          request.args['error_reason'],
          request.args['error_description']
      )
  session['google_token'] = (resp['access_token'], '')
  me = google.get('userinfo')
  user = User.query.filter_by(auth_server='Google',auth_server_id=me.data['id']).first()
  if user is None:
    createUser(me, 'Google')
    user = User.query.filter_by(auth_server='Google',auth_server_id=me.data['id']).first()
    session['user_id'] = user.id
    g.user = user.id
    return redirect(url_for('set_location'))

  session['user_id'] = user.id
  return redirect(url_for('findGame'))

@app.route('/g_login')
def g_login():
	return google.authorize(callback=url_for('g_authorized', _external=True))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/find')
def findGame():
	return render_template('find.html')

@app.route('/challenges')
def challenges():
	return render_template('challenges.html')

@app.route('/accepted')
def accepted():
	return render_template('accepted.html')

@app.route('/set_location', methods=['GET', 'POST'])
def set_location():
  if request.method == 'POST':
    input_location = request.form['address']
    geolocator = Nominatim()
    try:
      location = geolocator.geocode(input_location)
      session['user_loc_input'] = input_location
      session['user_lat'] = location.latitude
      session['user_long'] = location.longitude      
    except:
      location = None
    return render_template('set_location.html', location=location)
  
  return render_template('set_location.html')

@app.route('/set_profile', methods=['GET', 'POST'])
def set_profile():
  if request.method == 'POST':
    user = User.query.filter_by(id=session['user_id']).first()
    user.distance = request.form['distance']
    user.contact = request.form['contact']
    user.about_me = request.form['description']
    user.loc_input = session['user_loc_input']
    user.loc_latitude = session['user_lat']
    user.loc_longitude = session['user_long']
    db.session.commit()
    return redirect(url_for('findGame'))

  return render_template('set_profile.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    g.user == None
    return redirect(url_for('index'))

@app.before_request
def get_current_user():
	g.user = session.get('user_id', None)


#GEOCODE DISTANCE TESTING
@app.route('/create_geo_user')
def create_geo_user():
  geo_user = GeoUserTest(latitude="38" , longitude="121" )
  db.session.add(geo_user)

  geo_user2 = GeoUserTest(latitude="39" , longitude="122" )
  db.session.add(geo_user2)

  geo_user3 = GeoUserTest(latitude="40" , longitude="123" )
  db.session.add(geo_user3)

  db.session.commit()
  return 'geo user created'

@app.route('/find_distance')
def find_distance():
  my_distance = (37.3897202, -122.0941618)
  radius = 20
  users = User.query.all()
  
  
  #users = db.session.query(User).all()
  
  distances = [dict([
                    ("id", user.id),
                    #("dist_apart", distance(my_distance, (user.loc_latitude, user.loc_longitude))),
                    ("dist_apart", "%.1f" % vincenty(my_distance, (user.loc_latitude, user.loc_longitude)).miles),
                    ("bio", user.about_me),
                    ("name", user.name),
                    ("contact", user.contact),
                    ]) for user in users if vincenty(my_distance, (user.loc_latitude, user.loc_longitude)).miles < 20 if user.id != session['user_id']]

  #return 'no error'
  return jsonify(distances[0])