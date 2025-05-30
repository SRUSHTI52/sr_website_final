# import json
# from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
# from flask_sqlalchemy import SQLAlchemy
# from datetime import datetime,timedelta
# import razorpay
# from functools import wraps
# import jwt
# import os
# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from dotenv import load_dotenv
# from authlib.integrations.flask_client import OAuth
#
# load_dotenv()
#
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'PAYMENT_APP'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///payment.db'
#
# # Google OAuth Configuration
# GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "994209278643-os9co7hoj3fhdbstov9bpk294mcqtp18.apps.googleusercontent.com")
# GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "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")
# app.config['GOOGLE_CLIENT_ID'] = GOOGLE_CLIENT_ID
# app.config['GOOGLE_CLIENT_SECRET'] = GOOGLE_CLIENT_SECRET
# app.config['GOOGLE_DISCOVERY_URL'] = (
#     "https://accounts.google.com/.well-known/openid-configuration"
# )
#
# # Enable insecure transport for development
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
#
# EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
# EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
# EMAIL_USER = os.getenv("EMAIL_USER", "ananyapersona2203@gmail.com")
# EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "pppqkuzfxpmvnlqm")
# EMAIL_FROM = os.getenv("EMAIL_FROM", "App Support Team <app.support@srmd.org>")
#
# db = SQLAlchemy(app)
#
# # OAuth Setup
# oauth = OAuth(app)
# google = oauth.register(
#     name='google',
#     client_id=GOOGLE_CLIENT_ID,
#     client_secret=GOOGLE_CLIENT_SECRET,
#     server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
#     client_kwargs={
#         'scope': 'openid email profile',
#     }
# )
#
# app.config['ADMIN_USERNAME'] = 'admin'
# app.config['ADMIN_PASSWORD'] = 'abc12345'
#
# # Login required decorator
# def admin_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'admin_logged_in' not in session:
#             return redirect(url_for('admin_login'))
#         return f(*args, **kwargs)
#     return decorated_function
#
# @app.route('/admin/login', methods=['GET', 'POST'])
# def admin_login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#         if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
#             session['admin_logged_in'] = True
#             return redirect(url_for('admin_dashboard'))
#         return 'Invalid credentials'
#     return render_template('admin_login.html')
#
# @app.route('/admin/dashboard')
# @admin_required
# def admin_dashboard():
#     users = User.query.all()
#     return render_template('admin_dashboard.html', users=users)
#
# @app.route('/admin/logout')
# def admin_logout():
#     session.pop('admin_logged_in', None)
#     return redirect(url_for('admin_login'))
#
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(120), nullable=False)
#     name = db.Column(db.String(120), nullable=False)
#     phone = db.Column(db.String(20), nullable=False)
#     amount = db.Column(db.String(120), nullable=False)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#
# def send_ebook_email(user_email, name):
#     try:
#         msg = MIMEMultipart()
#         msg['From'] = EMAIL_FROM
#         msg['To'] = user_email
#         msg['Subject'] = "Your Visa Guide E-Book from SR Counselling"
#
#         ebook_link = "https://drive.google.com/file/d/1qrj2s4qL3ZSKvIrwYeT_yXHpl9DTjHm5/view?usp=sharing"
#
#         body = f"""
#         Dear {name},
#
#         Thank you for choosing SR Counselling!
#
#         We are pleased to provide you with access to your Visa Guide eBook. Click the link below to access your copy:
#
#         {ebook_link}
#
#         This eBook is designed to guide you through every step of your visa application journey, making the process easier and more transparent.
#
#         If you have any questions or require further assistance, feel free to reach out to our support team at support@srcounselling.com.
#
#         Wishing you success in your visa application process!
#
#         Best regards,
#         The SR Counselling Team
#         """
#
#         msg.attach(MIMEText(body, 'plain'))
#
#         with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
#             server.starttls()
#             server.login(EMAIL_USER, EMAIL_PASSWORD)
#             server.send_message(msg)
#
#         return True
#     except Exception as e:
#         print(f"Email error: {str(e)}")
#         return False
#
# @app.route('/')
# def home():
#     return render_template('main.html')
#
# @app.route('/login')
# def login():
#     # Generate a unique nonce and store it in the session
#     nonce = os.urandom(16).hex()
#     session['nonce'] = nonce
#     return google.authorize_redirect(
#         url_for('authorize', _external=True),
#         nonce=nonce  # Pass the nonce to Google
#     )
#
# @app.route('/authorize')
# def authorize():
#     token = google.authorize_access_token()
#     id_token = token.get('id_token')
#
#     # Verify the ID token and validate the nonce
#     try:
#         user_info = google.parse_id_token(token, nonce=session['nonce'])
#     except Exception as e:
#         return f"Error verifying token: {str(e)}", 400
#
#     # Save user info to session
#     session['email'] = user_info['email']
#     session['name'] = user_info.get('name', 'User')
#     return redirect(url_for('index'))
#
# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect('/')
#
# @app.route('/success', methods=['GET', 'POST'])
# def success():
#     user_id = session.get('user_id')
#     if not user_id:
#         return redirect(url_for('home'))
#
#     user = User.query.get(user_id)
#     if not user:
#         return redirect(url_for('home'))
#
#     # Send email with ebook link
#     email_sent = send_ebook_email(user.email, user.name)
#
#     # Create success message
#     if email_sent:
#         message = "Success! The ebook link has been sent to your email."
#     else:
#         message = "Payment successful but there was an error sending the email. Please contact support."
#
#     return render_template('success.html', message=message)
#
# @app.route('/index', methods=['GET', 'POST'])
# def index():
#     # Retrieve user info from session
#     email = session.get('email', None)
#     name = session.get('name', None)
#
#     # Redirect to login if user is not authenticated
#     if not email:
#         return redirect(url_for('login'))
#
#     if request.method == "POST":
#         phone = request.form.get('phone')
#         amount = "199"  # Fixed amount for demonstration
#
#         # Create user with Google-authenticated details
#         user = User(email=email, name=name, phone=phone, amount=amount)
#         db.session.add(user)
#         db.session.commit()
#
#         # Store user_id in session
#         session['user_id'] = user.id
#
#         # Create Razorpay order
#         client = razorpay.Client(auth=("rzp_test_7J7sVsldr989wI", "UgVuwdWuIKSzwLfrRDlp4dYp"))
#         payment = client.order.create({
#             'amount': int(amount) * 100,
#             'currency': 'INR',
#             'payment_capture': '1'
#         })
#
#         return redirect(url_for('pay', payment_id=payment['id'], user_id=user.id))
#
#     # Render index page with prefilled email and name
#     return render_template('index.html', name=name, email=email)
#
# @app.route('/pay/<payment_id>/<user_id>', methods=['GET'])
# def pay(payment_id, user_id):
#     user = User.query.filter_by(id=user_id).first()
#     payment = {
#         'amount': int(user.amount) * 100,
#         'currency': 'INR',
#         'order_id': payment_id
#     }
#     return render_template('redirect_to_razorpay.html', payment=payment, user=user)
#
# if __name__ == '__main__':
#     app.debug = True
#     with app.app_context():
#         db.create_all()
#     app.run()

import json
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import razorpay
from functools import wraps
import jwt
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

load_dotenv()

app = Flask(__name__)
#app.config['SECRET_KEY'] = 'PAYMENT_APP'
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///payment.db'

# Google OAuth Configuration
# GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID",
#                              "994209278643-os9co7hoj3fhdbstov9bpk294mcqtp18.apps.googleusercontent.com")
# GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "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")
# app.config['GOOGLE_CLIENT_ID'] = GOOGLE_CLIENT_ID
# app.config['GOOGLE_CLIENT_SECRET'] = GOOGLE_CLIENT_SECRET
# app.config['GOOGLE_DISCOVERY_URL'] = (
#     "https://accounts.google.com/.well-known/openid-configuration"
# )
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
app.config['GOOGLE_DISCOVERY_URL'] = os.getenv("GOOGLE_DISCOVERY_URL")

# Google Drive API Configuration
# SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE", "srinternship-326485aaeb1a.json")
# EBOOK_FILE_ID = os.getenv("EBOOK_FILE_ID", "1qrj2s4qL3ZSKvIrwYeT_yXHpl9DTjHm5")  # Extracted from your Drive link
SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE")
EBOOK_FILE_ID = os.getenv("EBOOK_FILE_ID")


DRIVE_SCOPES = ['https://www.googleapis.com/auth/drive']

# Enable insecure transport for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
# EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
# EMAIL_USER = os.getenv("EMAIL_USER", "ananyapersona2203@gmail.com")
# EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "pppqkuzfxpmvnlqm")
# EMAIL_FROM = os.getenv("EMAIL_FROM", "App Support Team <app.support@srmd.org>")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM")

db = SQLAlchemy(app)

# OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile',
    }
)

# app.config['ADMIN_USERNAME'] = 'admin'
# app.config['ADMIN_PASSWORD'] = 'abc12345'
app.config['ADMIN_USERNAME'] = os.getenv("ADMIN_USERNAME")
app.config['ADMIN_PASSWORD'] = os.getenv("ADMIN_PASSWORD")


# Login required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        return 'Invalid credentials'
    return render_template('admin_login.html')


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_granted = db.Column(db.Boolean, default=False)


def grant_drive_access(user_email):
    """Grant view-only access to the eBook for a specific user email."""
    try:
        # Authenticate using the service account
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=DRIVE_SCOPES)
        service = build('drive', 'v3', credentials=credentials)

        # Permission configuration
        user_permission = {
            'type': 'user',
            'role': 'reader',
            'emailAddress': user_email
        }

        # Add the permission to the file
        service.permissions().create(
            fileId=EBOOK_FILE_ID,
            body=user_permission,
            fields='id',
            sendNotificationEmail=False  # We'll send our own email
        ).execute()

        return True
    except HttpError as error:
        print(f"Drive API error: {str(error)}")
        return False


def send_ebook_email(user_email, name):
    try:
        # First grant access to the Drive file
        access_granted = grant_drive_access(user_email)

        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = user_email
        msg['Subject'] = "Your Visa Guide E-Book from SR Counselling"

        ebook_link = f"https://drive.google.com/file/d/{EBOOK_FILE_ID}/view?usp=sharing"

        # Modify the message based on whether access was granted
        access_message = ""
        if access_granted:
            access_message = "We've already granted you access to the document - no need to request access."
        else:
            access_message = "If prompted to request access, please do so and our team will approve it shortly."

        body = f"""
        Dear {name},

        Thank you for choosing SR Counselling!

        We are pleased to provide you with access to your Visa Guide eBook. Click the link below to access your copy:

        {ebook_link}
        PASSWORD: user_password
        {access_message}

        This eBook is designed to guide you through every step of your visa application journey, making the process easier and more transparent.

        If you have any questions or require further assistance, feel free to reach out to our support team at support@srcounselling.com.

        Wishing you success in your visa application process!

        Best regards,
        The SR Counselling Team
        """

        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)

        return access_granted
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False


@app.route('/')
def home():
    return render_template('main.html')


@app.route('/login')
def login():
    # Generate a unique nonce and store it in the session
    nonce = os.urandom(16).hex()
    session['nonce'] = nonce
    return google.authorize_redirect(
        url_for('authorize', _external=True),
        nonce=nonce  # Pass the nonce to Google
    )


@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    id_token = token.get('id_token')

    # Verify the ID token and validate the nonce
    try:
        user_info = google.parse_id_token(token, nonce=session['nonce'])
    except Exception as e:
        return f"Error verifying token: {str(e)}", 400

    # Save user info to session
    session['email'] = user_info['email']
    session['name'] = user_info.get('name', 'User')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
@app.route('/success', methods=['GET', 'POST'])
def success():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('home'))

    # Only send email if it hasn't been done yet
    if not user.access_granted:
        # Send email with ebook link and grant access
        access_granted = send_ebook_email(user.email, user.name)

        # Update user record
        if access_granted:
            user.access_granted = True
            db.session.commit()
            message = "Success! The ebook link has been sent to your email and access has been granted automatically."
        else:
            message = "Payment successful! The ebook link has been sent to your email, but there was an issue granting automatic access. Please request access if needed."
    else:
        message = "Your payment has already been processed and access granted. Check your email for the ebook link."

    ebook_link = f"https://drive.google.com/file/d/{EBOOK_FILE_ID}/view?usp=sharing"
    return render_template('success.html', message=message, ebook_link=ebook_link)
#
# @app.route('/index', methods=['GET', 'POST'])
# def index():
#     # Retrieve user info from session
#     email = session.get('email', None)
#     name = session.get('name', None)
#
#     # Redirect to login if user is not authenticated
#     if not email:
#         return redirect(url_for('login'))
#
#     if request.method == "POST":
#         phone = request.form.get('phone')
#         amount = "199"  # Fixed amount for demonstration
#
#         # Create user with Google-authenticated details
#         user = User(email=email, name=name, phone=phone, amount=amount, access_granted=False)
#         db.session.add(user)
#         db.session.commit()
#
#         # Store user_id in session
#         session['user_id'] = user.id
#
#         # Create Razorpay order
#         client = razorpay.Client(auth=("rzp_test_7J7sVsldr989wI", "UgVuwdWuIKSzwLfrRDlp4dYp"))
#         payment = client.order.create({
#             'amount': int(amount) * 100,
#             'currency': 'INR',
#             'payment_capture': '1'
#         })
#
#         return redirect(url_for('pay', payment_id=payment['id'], user_id=user.id))
#
#     # Render index page with prefilled email and name
#     return render_template('index.html', name=name, email=email)

@app.route('/index', methods=['GET', 'POST'])
def index():
    # Retrieve user info from session
    email = session.get('email', None)
    name = session.get('name', None)

    # Redirect to login if user is not authenticated
    if not email:
        return redirect(url_for('login'))

    # Check if user already has access to the eBook
    existing_user = User.query.filter_by(email=email, access_granted=True).first()
    if existing_user:
        # User already has access, redirect to a page that shows they already have access
        return redirect(url_for('already_purchased'))

    if request.method == "POST":
        phone = request.form.get('phone')
        # Phone validation should be done client-side as shown above
        amount = "199"  # Fixed amount for demonstration

        # Check again if user exists but hasn't been granted access
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            # Update existing user info
            existing_user.phone = phone
            existing_user.amount = amount
            db.session.commit()
            user_id = existing_user.id
        else:
            # Create new user
            user = User(email=email, name=name, phone=phone, amount=amount, access_granted=False)
            db.session.add(user)
            db.session.commit()
            user_id = user.id

        # Store user_id in session
        session['user_id'] = user_id

        # Create Razorpay order
        #client = razorpay.Client(auth=("rzp_test_7J7sVsldr989wI", "UgVuwdWuIKSzwLfrRDlp4dYp"))
        client = razorpay.Client(auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")))
        payment = client.order.create({
            'amount': int(amount) * 100,
            'currency': 'INR',
            'payment_capture': '1'
        })

        return redirect(url_for('pay', payment_id=payment['id'], user_id=user_id))

    # Render index page with prefilled email and name
    return render_template('index.html', name=name, email=email)


@app.route('/already_purchased')
def already_purchased():
    email = session.get('email', None)
    name = session.get('name', None)

    # Ensure user is logged in
    if not email:
        return redirect(url_for('login'))

    # Ensure user actually has access
    user = User.query.filter_by(email=email, access_granted=True).first()
    if not user:
        return redirect(url_for('index'))

    ebook_link = f"https://drive.google.com/file/d/{EBOOK_FILE_ID}/view?usp=sharing"

    return render_template('already_purchased.html',
                           name=name,
                           email=email,
                           ebook_link=ebook_link)


@app.route('/check_ebook_access')
def check_ebook_access():
    email = session.get('email', None)

    # If not logged in, proceed to login
    if not email:
        return redirect(url_for('login'))

    # Check if user already has access
    existing_user = User.query.filter_by(email=email, access_granted=True).first()
    if existing_user:
        # User already has access, redirect to already purchased page
        return redirect(url_for('already_purchased'))
    else:
        # User needs to purchase, redirect to index
        return redirect(url_for('index'))

@app.route('/pay/<payment_id>/<user_id>', methods=['GET'])
def pay(payment_id, user_id):
    user = User.query.filter_by(id=user_id).first()
    payment = {
        'amount': int(user.amount) * 100,
        'currency': 'INR',
        'order_id': payment_id
    }
    return render_template('redirect_to_razorpay.html', payment=payment, user=user)


if __name__ == '__main__':
    app.debug = True
    with app.app_context():
        db.create_all()
    app.run()