from .__init__ import db
from flask import current_app
from flask_login import UserMixin
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from sqlalchemy.ext.hybrid import hybrid_property, Comparator, hybrid_method
from sqlalchemy import func

# Custom comparator for case-insensitive email comparison
class CaseInsensitiveComparator(Comparator):
    def __eq__(self, other):
        return func.lower(self.__clause_element__()) == func.lower(other)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(1500), unique=True, nullable=False)
    pwd = db.Column(db.String(225), nullable=True)
    is_oauth = db.Column(db.Boolean, default=False)

    

    def __init__(self, username, email, pwd=None, is_oauth=False):
        self.username = username
        self.email = email
        self.pwd = pwd
        self.is_oauth = is_oauth

    
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=expires_sec)['user_id']
        except Exception as e:
            print(f"Token verification error:{e}")
            return None
        return User.query.get(user_id)


    @hybrid_property
    def email(self):
        return self.email

    @email.setter
    def email(self, value):
        self.email = value

    @hybrid_method
    def email_equals(self, other_email):
        return func.lower(self.email) == func.lower(other_email)

    @staticmethod
    def email_insensitive_search(email):
        return User.query.filter(User.email_equals(email))

    def __repr__(self):
        return '<User %r>' % self.email

def get_password(email):
    user = User.email_insensitive_search(email).first()
    if user:
        return user.pwd
    else:
        return None

    
