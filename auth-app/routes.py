from flask import (
    render_template,
    redirect,
    flash,
    url_for,
    session,
    request
)
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
import os
from flask_bcrypt import check_password_hash

from flask_login import (
    login_user,
    current_user,
    logout_user,
    login_required,
)
from flask_mail import Message
from .__init__ import create_app,db,login_manager,bcrypt, mail
from .models import User, get_password
from .forms import LoginForm,RegisterForm, RequestResetForm, ResetPasswordForm
import re

app = create_app()

with app.app_context():
    db.create_all()
    print("Database created successfully!")


# Load Google OAuth credentials from environment variables
GOOGLE_CLIENT_ID = os.getenv['GOOGLE_CLIENT_ID']
GOOGLE_CLIENT_SECRET = os.getenv['GOOGLE_CLIENT_SECRET']
GOOGLE_DISCOVERY_URL = os.getenv['GOOGLE_DISCOVERY_URL']

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# Home route
@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():

    return render_template("index.html",title="Home")


# Login route
@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data.lower()

        user = User.query.filter_by(email=email).first()


        password = get_password(email)

        if form.validate_on_submit():

            try:
                if user:
                    if password is None:
                        flash(f"Click <strong>Forgot password</strong> to reset password for {email}", "info")
                        return redirect(url_for("login"))
                    elif check_password_hash(user.pwd, form.pwd.data):
                        login_user(user)
                        return redirect(url_for('index'))
                    else:
                        flash("Invalid password!", "danger")
                else:
                    flash("Email does not exist!", "danger")
            except Exception as e:
                flash(e, "danger")

    return render_template("login.html",form=form) 

# Register route
@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        pwd = form.pwd.data
        username = form.username.data

        if not username or not email or not pwd:
            flash(f"All fields are required", "danger")
        if len(pwd) < 8:
            flash("Password must be at least 8 characters long", "danger")
            return redirect(url_for('register'))
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address", "danger")
            return redirect(url_for('register'))
    
        try:    
            newuser = User(
                username=username,
                email=email,
                pwd=bcrypt.generate_password_hash(pwd).decode('utf-8')
            )
    
            db.session.add(newuser)
            db.session.commit()
            print("Account created successfully!")
            flash(f"Account Succesfully created", "success")
            return redirect(url_for('login'))

        
        except Exception as e:
            db.session.rollback()
            if 'UNIQUE constraint failed: user.username' in str(e):
                flash("Username has been taken", "danger")
            elif 'UNIQUE contstraint failed: user.email' in str(e):
                flash("Email already exists", "danger")
            else:
                flash("An error occurred, try again", "danger")
            return redirect(url_for('register'))
    

    return render_template("register.html", form=form)
    



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# main_bp = Blueprint('main', __name__)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RequestResetForm()
    if request.method == 'POST':
        email =form.email.data.lower()
        print(f"Email entered: {email}")  # Debugging print
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"User found: {user.email}")  # Debugging print
            send_reset_email(user)
            flash(f'An email has been sent to {user.email} with instructions to reset your password.', 'info')
        else:
            print("User not found.")  # Debugging print
            flash('Email not found. Please check your email address.', 'warning')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    print(f"Token is received:{token}")
    if current_user.is_authenticated:
        print("User is authenticated. Redirecting to home.")
        return redirect(url_for('index'))
    user = User.verify_reset_token(token.encode())  #encode token to bytes

    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.pwd = hashed_password
        try:
            db.session.commit()
            print(f"Password updated for user {user.id}")
            flash('Your password has been updated! You are now able to log in', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error updating password: {e}")
            flash('An error occurred while updating the password. Please try again', 'danger')
        return redirect(url_for('login'))
    print("Rendering reset_token.html")
    return render_template('reset_token.html', title='Reset Password', form=form)

def send_reset_email(user):
    if isinstance(user, User):
        token = user.get_reset_token()
        msg = Message('Password Reset Request',
                    sender='noreply@demo.com',
                    recipients=[user.email])
        msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route("/dashboard")
@login_required
def dashboard():
    
    return render_template('dashboard.html', title="Dashboard")

@app.route('/google-login')
def google_login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = f"{authorization_endpoint}?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri=http://127.0.0.1:5000/auth/google/callback&scope=openid%20email%20profile&access_type=offline&prompt=select_account"
    return redirect(request_uri)

@app.route('/auth/google/callback')
def google_callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url = token_endpoint
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': "http://127.0.0.1:5000/auth/google/callback",
        'grant_type': 'authorization_code'
    }
    token_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    token_response = requests.post(token_url, data=token_data, headers=token_headers)
    token_response_json = token_response.json()

    if 'error' in token_response_json:
        return f"Token request failed: {token_response_json['error']}"

    id_info = id_token.verify_oauth2_token(
        token_response_json.get("id_token"), google_requests.Request(), GOOGLE_CLIENT_ID
    )

    email = id_info['email']
    user = User.query.filter_by(email=email).first()

    if user is None:
        user = User(
            username=id_info['name'],  # or any other default username
            email=email,
            pwd=None,  # Since the user is using Google OAuth, no need to set a password
            is_oauth=True
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session['user_id'] = id_info['sub']
    session['email'] = email

    return redirect(url_for('index'))





# if __name__ == "__main__":
#     app.run(debug=True)
