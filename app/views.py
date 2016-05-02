from flask import render_template, url_for, session, request, redirect, jsonify, g
from flask_oauthlib.client import OAuthException
from geopy.geocoders import Nominatim
from geopy.distance import vincenty
from app import app, db, google, facebook
from models import User, Matches, GeoUserTest
from geocoder import distance
from operator import itemgetter

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

@app.route('/fb_login')
def fb_login():
  return login('Facebook')

@app.route('/g_login')
def g_login():
  return login('Google')

@app.route('/login')
def login(server_name):
  if server_name == "Facebook":
    callback = url_for(
      'facebook_authorized',
      next=request.args.get('next') or request.referrer or None,
      _external=True
    )
    return facebook.authorize(callback=callback)

  return google.authorize(callback=url_for('g_authorized', _external=True))

def setUser(server_name, me):
  user = User.query.filter_by(auth_server=server_name,auth_server_id=me.data['id']).first()
  if user is None:
    createUser(me, server_name)
    user = User.query.filter_by(auth_server=server_name,auth_server_id=me.data['id']).first()
    session['user_id'] = user.id
    g.user = user.id
    return redirect(url_for('set_location'))

  session['user_id'] = user.id
  return redirect(url_for('findGame'))

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
  return setUser('Facebook', me)

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')

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
  return setUser('Google', me)

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/set_location', methods=['GET', 'POST'])
@app.route('/set_location/<string:set_type>', methods=['GET', 'POST'])
def set_location(set_type=None):
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
    
    if set_type == "update":
      return render_template('set_location.html', location=location, type="update")

    return render_template('set_location.html', location=location)

  if set_type == "update":
    current_user = User.query.filter_by(id=session['user_id']).first()
    return render_template('set_location.html', type="update", current_loc=current_user.loc_input)
  
  return render_template('set_location.html')

@app.route('/update_location')
def update_location():
  return redirect(url_for("set_location", set_type="update"))

@app.route('/set_profile', methods=['GET', 'POST'])
@app.route('/set_profile/<string:set_type>', methods=['GET', 'POST'])
def set_profile(set_type=None):
  if request.method == 'POST':
    user = User.query.filter_by(id=session['user_id']).first()
    user.dist_apart = request.form['distance']
    user.contact = request.form['contact']
    user.about_me = request.form['description']
    user.loc_input = session['user_loc_input']
    user.loc_latitude = session['user_lat']
    user.loc_longitude = session['user_long']
    db.session.commit()
    return redirect(url_for('findGame'))

  if set_type == "update":
    current_user = User.query.filter_by(id=session['user_id']).first()
    return render_template('set_profile.html', type="update", distance=current_user.dist_apart, contact=current_user.contact, description=current_user.about_me)

  return render_template('set_profile.html')

@app.route('/update_profile')
def update_profile():
  #current_user = User.query.filter_by(id=session['user_id']).first()
  #return render_template('set_profile.html', type="update", distance=current_user.dist_apart, contact=current_user.contact, description=current_user.about_me)
  return redirect(url_for("set_profile", set_type="update"))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    g.user == None
    return redirect(url_for('index'))

@app.before_request
def get_current_user():
	g.user = session.get('user_id', None)

@app.route('/find')
def findGame():
  users = User.query.all()
  current_user = User.query.filter_by(id=session['user_id']).first()
  
  current_matches = Matches.query.filter((Matches.challenger_id==session['user_id']) | (Matches.challenged_id==session['user_id']))
  matches = [match.challenged_id for match in current_matches if match.challenger_id == session['user_id']] + \
            [match.challenger_id for match in current_matches if match.challenged_id == session['user_id']]

  players = [dict([
                    ("id", user.id),
                    ("dist_apart", vincenty((current_user.loc_latitude, current_user.loc_longitude), (user.loc_latitude, user.loc_longitude)).miles),
                    ("bio", user.about_me),
                    ("pic", user.profile_pic),
                    ("name", user.name),
                    ("contact", user.contact),
                    ]) for user in users 
                        if vincenty((current_user.loc_latitude, current_user.loc_longitude), (user.loc_latitude, user.loc_longitude)).miles < current_user.dist_apart 
                        if user.id != current_user.id
                        if user.id not in matches]

  sorted_players = sorted(players, key=itemgetter('dist_apart'), reverse=False) 
  return render_template("find.html", players=sorted_players, state="find")

@app.route('/update_find/<int:user>/<string:action>')
def update_find(user, action):
  new_match = Matches(challenger_id=session['user_id'],
                      challenger_action=action,
                      challenged_id=user)
  db.session.add(new_match)
  db.session.commit()
  return redirect(url_for('findGame'))

@app.route('/update_challenge/<int:user>/<string:action>')
def update_challenge(user, action):
  match = Matches.query.filter(Matches.challenged_id==session['user_id'],Matches.challenger_id==user).first()

  if action == "True":
    match.challenged_action = True
  else:
    match.challenged_action = False
  
  db.session.commit()
  return redirect(url_for('challenges'))

@app.route('/challenges')
def challenges():
  users = User.query.all()
  current_user = User.query.filter_by(id=session['user_id']).first()
  current_matches = Matches.query.filter(Matches.challenged_id==session['user_id'])
  matches = [match.challenger_id for match in current_matches 
                                  if match.challenger_action == True
                                  if match.challenged_action == None]
  players = [dict([
                    ("id", user.id),
                    ("dist_apart", vincenty((current_user.loc_latitude, current_user.loc_longitude), (user.loc_latitude, user.loc_longitude)).miles),
                    ("bio", user.about_me),
                    ("pic", user.profile_pic),
                    ("name", user.name),
                    ("contact", user.contact),
                    ]) for user in users 
                        #if user.id != current_user.id
                        if user.id in matches]

  sorted_players = sorted(players, key=itemgetter('dist_apart'), reverse=False) 
  return render_template("find.html", players=sorted_players, state="challenges")


@app.route('/accepted')
def accepted():
  users = User.query.all()
  current_user = User.query.filter_by(id=session['user_id']).first()
  current_matches = Matches.query.filter((Matches.challenger_id==session['user_id']) | (Matches.challenged_id==session['user_id']))
  matches = [match.challenged_id for match in current_matches 
                                  if match.challenger_id == session['user_id']
                                  if match.challenger_action == True
                                  if match.challenged_action == True] + \
            [match.challenger_id for match in current_matches 
                                  if match.challenged_id == session['user_id']
                                  if match.challenger_action == True
                                  if match.challenged_action == True]

  players = [dict([
                    ("id", user.id),
                    ("dist_apart", vincenty((current_user.loc_latitude, current_user.loc_longitude), (user.loc_latitude, user.loc_longitude)).miles),
                    ("bio", user.about_me),
                    ("pic", user.profile_pic),
                    ("name", user.name),
                    ("contact", user.contact),
                    ]) for user in users 
                        if user.id in matches]

  sorted_players = sorted(players, key=itemgetter('dist_apart'), reverse=False) 
  return render_template("find.html", players=sorted_players, state="accepted")


#CREATE TEST USERS
@app.route('/create_test_user')
def create_test_user():
  test_user = User(
                  auth_server="test",
                  auth_server_id=1,
                  name='c',
                  email='c',
                  loc_latitude='37.3082567',
                  loc_longitude='-122.2126541',
                  about_me="Hello I am a person Hello I am a personHello I am a personHello I am a personHello I am a personHell",
                  profile_pic='https://lh5.googleusercontent.com/-DTsx6olRHB8/AAAAAAAAAAI/AAAAAAAAADY/e4nE2R-t9Zk/photo.jpg'
                   )
  db.session.add(test_user)
  db.session.commit()

  return 'test user created'

@app.route('/test_action/<string:variable>/<string:var2>')
def test_action(variable, var2):
  return 'hi'


@app.route('/url_for')
def url_for_test():
  return redirect(url_for('test_action', variable='hi', var2="hello"))

@app.route('/create_test_match')
def create_test_match():
  new_match = Matches(challenger_id=12,
                      challenger_action=True,
                      challenged_id=10,
                      challenged_action=True,)
  db.session.add(new_match)
  db.session.commit()  

  return 'test matches created'

