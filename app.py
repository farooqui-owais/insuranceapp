# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.urandom(24) # A strong secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to login page if not authenticated

# app.py (add these classes after app and db initialization)

# User Model for Flask-Login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    policies = db.relationship('Policy', backref='owner', lazy=True)
    claims = db.relationship('Claim', backref='claimer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# Policy Model
class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    policy_number = db.Column(db.String(50), unique=True, nullable=False)
    policy_type = db.Column(db.String(50), nullable=False) # e.g., 'Auto', 'Health', 'Life', 'Home'
    coverage_amount = db.Column(db.Float, nullable=False)
    premium_amount = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.String(10), nullable=False) # Store as YYYY-MM-DD string
    end_date = db.Column(db.String(10), nullable=False) # Store as YYYY-MM-DD string
    status = db.Column(db.String(20), default='Active') # e.g., 'Active', 'Expired', 'Cancelled'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Policy {self.policy_number} - {self.policy_type}>'

# Claim Model
class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    claim_number = db.Column(db.String(50), unique=True, nullable=False)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    claim_date = db.Column(db.String(10), nullable=False) # Store as YYYY-MM-DD string
    status = db.Column(db.String(20), default='Pending') # e.g., 'Pending', 'Approved', 'Rejected'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    policy = db.relationship('Policy', backref='claims', lazy=True)

    def __repr__(self):
        return f'<Claim {self.claim_number} - {self.status}>'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# app.py (add these routes after the home route)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered. Please use a different email or login.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# app.py (add these routes after dashboard)
import datetime # Import at the top of app.py

@app.route('/policies')
@login_required
def policies():
    user_policies = Policy.query.filter_by(user_id=current_user.id).all()
    return render_template('policies.html', policies=user_policies)

@app.route('/add_policy', methods=['GET', 'POST'])
@login_required
def add_policy():
    if request.method == 'POST':
        policy_number = request.form.get('policy_number')
        policy_type = request.form.get('policy_type')
        coverage_amount = float(request.form.get('coverage_amount'))
        premium_amount = float(request.form.get('premium_amount'))
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        status = request.form.get('status')

        # Basic validation for policy number uniqueness
        existing_policy = Policy.query.filter_by(policy_number=policy_number).first()
        if existing_policy:
            flash('Policy number already exists. Please use a unique one.', 'error')
            return redirect(url_for('add_policy'))

        new_policy = Policy(
            policy_number=policy_number,
            policy_type=policy_type,
            coverage_amount=coverage_amount,
            premium_amount=premium_amount,
            start_date=start_date,
            end_date=end_date,
            status=status,
            user_id=current_user.id
        )
        db.session.add(new_policy)
        db.session.commit()
        flash('Policy added successfully!', 'success')
        return redirect(url_for('policies'))
    return render_template('add_policy.html')

# app.py (add these routes after add_policy)

@app.route('/policy/<int:policy_id>')
@login_required
def view_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if policy.user_id != current_user.id:
        flash('You do not have permission to view this policy.', 'error')
        return redirect(url_for('policies'))
    return render_template('view_policy.html', policy=policy)

@app.route('/policy/<int:policy_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if policy.user_id != current_user.id:
        flash('You do not have permission to edit this policy.', 'error')
        return redirect(url_for('policies'))

    if request.method == 'POST':
        policy.policy_type = request.form.get('policy_type')
        policy.coverage_amount = float(request.form.get('coverage_amount'))
        policy.premium_amount = float(request.form.get('premium_amount'))
        policy.start_date = request.form.get('start_date')
        policy.end_date = request.form.get('end_date')
        policy.status = request.form.get('status')

        # Note: policy_number is typically not editable after creation
        # If you need to allow it, add validation for uniqueness here.

        db.session.commit()
        flash('Policy updated successfully!', 'success')
        return redirect(url_for('view_policy', policy_id=policy.id))
    return render_template('edit_policy.html', policy=policy)

@app.route('/policy/<int:policy_id>/delete', methods=['POST'])
@login_required
def delete_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if policy.user_id != current_user.id:
        flash('You do not have permission to delete this policy.', 'error')
        return redirect(url_for('policies'))

    # Delete associated claims first to avoid foreign key constraints
    Claim.query.filter_by(policy_id=policy.id).delete()
    db.session.delete(policy)
    db.session.commit()
    flash('Policy and associated claims deleted successfully!', 'success')
    return redirect(url_for('policies'))


# app.py (add these routes after policy management)

@app.route('/claims')
@login_required
def claims():
    user_claims = Claim.query.filter_by(user_id=current_user.id).all()
    return render_template('claims.html', claims=user_claims)

@app.route('/file_claim', methods=['GET', 'POST'])
@login_required
def file_claim():
    user_policies = Policy.query.filter_by(user_id=current_user.id, status='Active').all()
    if not user_policies:
        flash('You need at least one active policy to file a claim.', 'error')
        return redirect(url_for('add_policy'))

    if request.method == 'POST':
        policy_id = request.form.get('policy_id')
        description = request.form.get('description')
        claim_date = request.form.get('claim_date')

        # Generate a simple claim number (you might want a more robust system)
        import uuid
        claim_number = str(uuid.uuid4())[:8].upper() # First 8 chars of a UUID

        new_claim = Claim(
            claim_number=claim_number,
            policy_id=policy_id,
            description=description,
            claim_date=claim_date,
            user_id=current_user.id
        )
        db.session.add(new_claim)
        db.session.commit()
        flash('Claim filed successfully! Your claim number is: ' + claim_number, 'success')
        return redirect(url_for('claims'))
    return render_template('file_claim.html', policies=user_policies)

# app.py (add these routes after file_claim)

@app.route('/claim/<int:claim_id>')
@login_required
def view_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    if claim.user_id != current_user.id:
        flash('You do not have permission to view this claim.', 'error')
        return redirect(url_for('claims'))
    return render_template('view_claim.html', claim=claim)

@app.route('/claim/<int:claim_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    if claim.user_id != current_user.id:
        flash('You do not have permission to edit this claim.', 'error')
        return redirect(url_for('claims'))

    # Only allow editing of description and claim_date for simplicity
    # Status changes would typically be handled by an admin or internal process
    if request.method == 'POST':
        claim.description = request.form.get('description')
        claim.claim_date = request.form.get('claim_date')
        db.session.commit()
        flash('Claim updated successfully!', 'success')
        return redirect(url_for('view_claim', claim_id=claim.id))
    return render_template('edit_claim.html', claim=claim)

@app.route('/claim/<int:claim_id>/delete', methods=['POST'])
@login_required
def delete_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    if claim.user_id != current_user.id:
        flash('You do not have permission to delete this claim.', 'error')
        return redirect(url_for('claims'))

    db.session.delete(claim)
    db.session.commit()
    flash('Claim deleted successfully!', 'success')
    return redirect(url_for('claims'))

# Define a simple route
@app.route('/')
def home():
    return "<h1>Welcome to the Insurance App!</h1><p><a href='/login'>Login</a> | <a href='/register'>Register</a></p>"



if __name__ == '__main__':
    app.run(debug=True) # Run in debug mode for development
