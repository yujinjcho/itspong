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

def setUser(server_name, server_id):
  user = User.query.filter_by(auth_server=server_name,auth_server_id=server_id).first()
  if user is None:
    createUser(me, server_name)
    user = User.query.filter_by(auth_server=server_name,auth_server_id=server_id).first()
    session['user_id'] = user.id
    return redirect(url_for('set_location'))

  session['user_id'] = user.id
  return user.name + ' is logged in'


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
  return setUser('Google', me.data['id'])


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
  return setUser('Facebook', me.data['id'])