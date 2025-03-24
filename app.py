import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db  # Import db from extensions.py
from models import User, Incident  # Import models
from flask_mail import Mail, Message

# Initialize the app and its configurations
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus_security.db'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "your_secret_key")

# Secure Mail Credentials from Environment Variables
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'dutlostandfound@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'jyhw jjpm gcjr tvmz'  # Your 

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Flask-Mail
mail = Mail(app)

# Create database tables
with app.app_context():
    db.create_all()

# Pre-create an admin user (if not already in database)
with app.app_context():
    admin = User.query.filter_by(email="admin@dut4life.ac.za").first()
    if not admin:
        admin = User(
            email="admin@dut4life.ac.za",
            password=generate_password_hash("admin123", method='pbkdf2:sha256'),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: admin@dut4life.ac.za")
    else:
        print("🔹 Admin user already exists!")

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        
        # Validate email domain
        if not email.endswith("@dut4life.ac.za"):
            flash("Only DUT members can register with a @dut4life.ac.za email address", "danger")
            return redirect(url_for('register'))

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for('login'))

        # Register new user
        new_user = User(email=email, password=password, role='student')
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check admin credentials
        if email == "admin@dut4life.ac.za" and password == "admin123":
            user = User.query.filter_by(email="admin@dut4life.ac.za").first()
            if user and user.role == 'admin':
                login_user(user)
                return redirect(url_for('admin_dashboard'))

        # Check database for users
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        incident_type = request.form.get('incident_type', '').strip()
        description = request.form.get('description', '').strip()

        if not incident_type:
            flash("Incident Type is required.", "danger")
            return redirect(url_for('report'))

        try:
            new_incident = Incident(
                user_id=current_user.id,
                incident_type=incident_type,
                description=description,
                timestamp=datetime.utcnow()
            )
            db.session.add(new_incident)
            db.session.commit()

            msg = Message(
                subject='New Incident Reported',
                sender=app.config['MAIL_USERNAME'],
                recipients=['22329286@dut4life.ac.za'],
                body=f"""
                A new incident has been reported:

                - Incident Type: {incident_type}
                - Description: {description or 'N/A'}
                - Reported By: {current_user.email}

                Please log in to review the details.
                """
            )
            mail.send(msg)

            flash("Incident reported successfully. Admin has been notified.", "success")
            return redirect(url_for('confirmation')) 

        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while reporting: {str(e)}", "danger")

    return render_template('report.html')

@app.route('/confirmation/<int:incident_id>')
@login_required
def confirmation(incident_id):
    # Retrieve incident from database
    incident = Incident.query.get_or_404(incident_id)

    return render_template('confirmation.html', incident=incident, user_email=current_user.email)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    incidents = Incident.query.all()
    return render_template('admin.html', incidents=incidents)

@app.route('/history')
@login_required
def history():
    incidents = Incident.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', incidents=incidents)

@app.route('/map')
def map_page():
    return render_template('map.html', api_key=os.environ.get("MAP_API_KEY"))  

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.phone = request.form['phone']
        db.session.commit()
        flash('Profile updated successfully!', "success")
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

if __name__ == '__main__':
    app.run(debug=True)
