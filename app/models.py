from datetime import datetime
from geocoder import distance
from sqlalchemy.ext.hybrid import hybrid_method

from app import db

class User(db.Model):
  #__tablename__ = 'users'

  id = db.Column(db.Integer, nullable=False, primary_key=True)
  auth_server = db.Column(db.String, nullable=False)
  auth_server_id = db.Column(db.String, nullable=False)
  created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
  name = db.Column(db.String, nullable=False)
  email = db.Column(db.String, nullable=False)
  loc_input = db.Column(db.String, default=None)
  loc_latitude = db.Column(db.String, default=None)
  loc_longitude = db.Column(db.String, default=None)
  #loc_city = db.Column(db.String, default=None)
  dist_apart = db.Column(db.Integer, default=None)
  contact = db.Column(db.String, default=None)
  about_me = db.Column(db.String(200), default='About Me')
  profile_pic = db.Column(db.String)

class GeoUserTest(db.Model):
  id = db.Column(db.Integer, nullable=False, primary_key=True)
  latitude = db.Column(db.String, default=None)
  longitude = db.Column(db.String, default=None)

  @hybrid_method
  #def calc_dist(self, latitude, longitude):    
  #  user_distance = distance((latitude, longitude), (self.latitude, self.longitude))
  def calc_dist(self):    
    user_distance = distance(("42.111", "125.111"), (self.latitude, self.longitude))
    return user_distance