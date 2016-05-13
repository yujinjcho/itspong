from datetime import datetime
from geocoder import distance
from sqlalchemy.ext.hybrid import hybrid_method

from app import db

class User(db.Model):

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    auth_server = db.Column(db.String, nullable=False)
    auth_server_id = db.Column(db.String, nullable=False)
    created = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False
    )
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    loc_input = db.Column(db.String, default=None)
    loc_latitude = db.Column(db.String, default=None)
    loc_longitude = db.Column(db.String, default=None)
    dist_apart = db.Column(db.Integer, default=None)
    contact = db.Column(db.String, default=None)
    about_me = db.Column(db.String(200), default='About Me')
    profile_pic = db.Column(db.String)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  # python 2
        except NameError:
            return str(self.id)  # python 3

class Matches(db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    created = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False
    )
    challenger_id = db.Column(db.Integer, nullable=False)
    challenger_action = db.Column(db.Boolean, default=None)
    challenged_id = db.Column(db.Integer, nullable=False)
    challenged_action = db.Column(db.Boolean, default=None)

class GeoUserTest(db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    latitude = db.Column(db.String, default=None)
    longitude = db.Column(db.String, default=None)