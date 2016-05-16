from operator import itemgetter
from flask import (
    render_template, 
    url_for, 
    session, 
    request, 
    redirect, 
    jsonify, 
    g, 
    flash
)
from flask_oauthlib.client import OAuthException
from flask.ext.login import (
    login_user, 
    logout_user, 
    login_required, 
    current_user
)
from geopy.geocoders import Nominatim
from geopy.distance import vincenty

from app import app, db, google, facebook, lm
from models import User, Matches

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.before_request
def get_current_user():
    g.user = current_user

@app.route('/')
def index():
    if g.user is not None and g.user.is_authenticated:
        return redirect(url_for('find_game'))
    return render_template('index.html')

def create_user(me, auth_server_name):  
    if auth_server_name == 'Facebook':
        profile_url = me.data['picture']['data']['url']
    else:
        profile_url = me.data['picture']
    
    new_user = User(
        auth_server=auth_server_name, 
        auth_server_id=me.data['id'],
        name=me.data['name'],
        email=me.data['email'],
        profile_pic=profile_url
    )  

    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)
    return new_user

def set_user(server_name, me):
    user = User.query.filter_by(
        auth_server=server_name, 
        auth_server_id=me.data['id']
    ).first()
    if user is None:
        user = create_user(me, server_name)
        return redirect(url_for('set_location'))

    login_user(user, remember=True)
    return redirect(url_for('find_game'))

@app.route('/login/<string:server_name>')
def login(server_name):
    if server_name == "Facebook":
        callback = url_for(
            'facebook_authorized',
            next=request.args.get('next')
                or request.referrer 
                or None,
            _external=True
        )
        return facebook.authorize(callback=callback)

    return google.authorize(
        callback=url_for('g_authorized', _external=True)
    )

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
    me = facebook.get(
        '/me/?fields=email,name,id,picture.height(200).width(200)'
    )
    return set_user('Facebook', me)

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
    return set_user('Google', me)

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/set_location', methods=['GET', 'POST'])
@app.route('/set_location/<string:set_type>', methods=['GET', 'POST'])
@login_required
def set_location(set_type=None):
    user = User.query.filter_by(id=g.user.id).first()

    if request.method == 'POST':
        input_location = request.form['address']
        geolocator = Nominatim()
        try:
            location = geolocator.geocode(input_location)
            user.loc_input = input_location
            user.loc_latitude = location.latitude
            user.loc_longitude = location.longitude
            db.session.commit()
        except:
            location = None
        return render_template(
            'set_location.html', 
            location=location, 
            type=set_type
        )

    if set_type:
        loc_input = user.loc_input
    else:
        loc_input = None
    return render_template(
        'set_location.html', 
        type=set_type, 
        current_loc=loc_input
    )

def fill_profile(set_type, user):
    if set_type:
        return render_template(
            'set_profile.html',
            type=set_type,
            distance=user.dist_apart,
            contact=user.contact,
            description=user.about_me
        )
    return render_template('set_profile.html')

@app.route('/set_profile', methods=['GET', 'POST'])
@app.route('/set_profile/<string:set_type>', methods=['GET', 'POST'])
@login_required
def set_profile(set_type=None):
    if request.method == 'POST':
        user = User.query.filter_by(id=g.user.id).first()    
    try:
        user.dist_apart = request.form['distance']
        user.contact = request.form['contact']
        user.about_me = request.form['description']
        db.session.commit()
    except:
        db.session.rollback()
        return fill_profile(set_type, g.user)
    return redirect(url_for('find_game'))

    return fill_profile(set_type, g.user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/set_guest_location', methods=['GET', 'POST'])
def set_guest_location(set_type=None):
    if request.method == 'POST':
        input_location = request.form['address']
        geolocator = Nominatim()
        try:
            location = geolocator.geocode(input_location)
        except:
            location = None
        return render_template('set_location.html', location=location)

    return render_template('set_location.html')

def dict_w_dist(query_obj, guest=False, latitude=None, longitude=None):
    query_dict = query_obj.__dict__
    del query_dict['_sa_instance_state']
    if guest == True:
        query_dict['dist_apart'] = vincenty(
            (latitude, longitude),
            (query_dict["loc_latitude"], query_dict["loc_longitude"])
        ).miles
        query_dict['name'] = query_dict['name'][:1] + '.'
    else:
        query_dict['dist_apart'] = vincenty(
            (g.user.loc_latitude, g.user.loc_longitude),
            (query_dict["loc_latitude"], query_dict["loc_longitude"])
        ).miles 
    return query_dict

@app.route('/view_players/<string:latitude>/<string:longitude>')
def view_players(latitude, longitude):
    users = User.query.all()
    players = [
        dict_w_dist(user, guest=True, latitude=latitude, longitude=longitude)
        for user in users
        if vincenty(
            (latitude, longitude),
            (user.loc_latitude, user.loc_longitude)
        ).miles < 200
    ]

    sorted_players = sorted(
        players, 
        key=itemgetter('dist_apart'), 
        reverse=False
    ) 
    return render_template(
        "find.html", 
        players=sorted_players, 
        state="find", 
        name="Guest"
    )

def player_view(state, users, matches):
    if state == "find":
        players = [
            dict_w_dist(user) for user in users
            if vincenty(
                (g.user.loc_latitude, g.user.loc_longitude), \
                (user.loc_latitude, user.loc_longitude)
            ).miles < g.user.dist_apart 
            if user.id not in matches
        ]
    else:
         players = [
            dict_w_dist(user)
            for user in users
            if user.id in matches
        ]
    return sorted(players, key=itemgetter('dist_apart'), reverse=False) 

@app.route('/find')
@login_required
def find_game():
    state = 'find'
    users = User.query.filter(User.id != g.user.id).all()
    current_matches = Matches.query.filter(
        (Matches.challenger_id==g.user.id) | \
        (Matches.challenged_id==g.user.id)
    ) 
    
    matches1 = [
        match.challenged_id 
        for match in current_matches 
        if match.challenger_id == int(g.user.id)
    ]
    
    matches2 = [
        match.challenger_id 
        for match in current_matches 
        if match.challenged_id == int(g.user.id)
    ]

    matches = matches1 + matches2
    players = player_view(state, users, matches)
    return render_template("find.html", players=players, state=state)

@app.route('/update_find/<int:user>/<int:action>/<string:user_name>')
@login_required
def update_find(user, action, user_name):
    new_match = Matches(
        challenger_id=g.user.id,
        challenger_action=bool(action),
        challenged_id=user
    )
    db.session.add(new_match)
    db.session.commit()
    
    if action:
        flash(
            "Challenge sent to %s. If your challenge is accepted, \
            %s's contact info will appear on the Accepted tab." 
            % (user_name, user_name)
        ) 
    
    return redirect(url_for('find_game'))

@app.route('/update_challenge/<int:user>/<int:action>')
@login_required
def update_challenge(user, action):
    match = Matches.query.filter(
        Matches.challenged_id==g.user.id,Matches.challenger_id==user
    ).first()

    match.challenged_action = bool(action)
    db.session.commit()
    return redirect(url_for('challenges'))

@app.route('/challenges')
@login_required
def challenges():
    state = "challenges"
    users = User.query.filter(User.id != g.user.id).all()
    current_matches = Matches.query.filter(
        Matches.challenged_id==g.user.id
    )
    matches = [
        match.challenger_id 
        for match in current_matches 
        if match.challenger_action == True
        if match.challenged_action == None
    ]

    players = player_view(state, users, matches)
    return render_template(
        "find.html", 
        players=players, 
        state=state, 
        name=g.user.name
    )

@app.route('/accepted')
@login_required
def accepted():
    state="accepted"
    users = User.query.filter(User.id != g.user.id).all()
    current_matches = Matches.query.filter(
        (Matches.challenger_id==g.user.id) | \
        (Matches.challenged_id==g.user.id)
    )
    
    matches1 = [
        match.challenged_id 
        for match in current_matches 
        if match.challenger_id == int(g.user.id)
        if match.challenger_action and match.challenged_action
    ]
    matches2 = [
        match.challenger_id 
        for match in current_matches 
        if match.challenged_id == int(g.user.id)
        if match.challenger_action and match.challenged_action
    ]
    
    matches = matches1 + matches2
    players = player_view(state, users, matches)
    
    return render_template(
        "find.html", 
        players=players, 
        state=state, 
        name=g.user.name
    )
