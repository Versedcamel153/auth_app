from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
)

from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, EqualTo, Email, Regexp ,Optional
from wtforms import ValidationError
from .models import User

class RegisterForm(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(3, 20, message="Please provide a valid name"),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, " "numbers, dots or underscores",
            ),
        ]
    )
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    pwd = PasswordField(validators=[InputRequired(), Length(8, 72)])



    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered!")

    def validate_uname(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already taken!")

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    pwd = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])
    # Placeholder labels to enable form rendering
 

class RequestResetForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    submit = SubmitField("Request Password Reset")

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])
    confirm_password = PasswordField(
        validators=[
            InputRequired(),
            Length(8, 72),
            EqualTo("password", message="Passwords must match !"),
        ]
    )
    submit = SubmitField("Reset password")
