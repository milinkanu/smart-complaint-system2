"""
Smart Complaint & Service Tracking System
Main Flask Application

This application provides a complete complaint management system
for colleges/offices with user and admin functionality.
"""

import os
import uuid
import string
import random
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

from config import config

# Initialize Flask extensions
app = Flask(__name__)
app.config.from_object(config['default'])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== DATABASE MODELS ====================

class User(UserMixin, db.Model):
    """
    User model for storing user information
    Supports both regular users and admin users
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to complaints
    complaints = db.relationship('Complaint', backref='user', lazy=True, foreign_keys='Complaint.user_id')
    assigned_complaints = db.relationship('Complaint', backref='assigned_to_user', lazy=True, foreign_keys='Complaint.assigned_to')
    notes = db.relationship('ComplaintNote', backref='author', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Category(db.Model):
    """
    Category model for organizing complaint types
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Category {self.name}>'
    
    def to_dict(self):
        """Convert category object to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }


class Complaint(db.Model):
    """
    Complaint model for storing complaint information
    Tracks complaint status, priority, and details
    """
    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, urgent
    location = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, resolved, closed
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    attachment = db.Column(db.String(300), nullable=True)
    rating = db.Column(db.Integer, nullable=True)  # 1-5 stars
    feedback = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to notes
    notes = db.relationship('ComplaintNote', backref='complaint', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Complaint {self.tracking_id}>'
    
    def to_dict(self):
        """Convert complaint object to dictionary"""
        return {
            'id': self.id,
            'tracking_id': self.tracking_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'Unknown',
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'priority': self.priority,
            'location': self.location,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'assigned_to_name': self.assigned_to_user.username if self.assigned_to_user else 'Not Assigned',
            'attachment': self.attachment,
            'rating': self.rating,
            'feedback': self.feedback,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ComplaintNote(db.Model):
    """
    ComplaintNote model for internal notes on complaints
    Allows admins and staff to add notes to complaints
    """
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ComplaintNote {self.id}>'
    
    def to_dict(self):
        """Convert note object to dictionary"""
        return {
            'id': self.id,
            'complaint_id': self.complaint_id,
            'user_id': self.user_id,
            'author_name': self.author.username if self.author else 'Unknown',
            'note': self.note,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ==================== HELPER FUNCTIONS ====================

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))


def generate_tracking_id():
    """Generate unique tracking ID for complaints"""
    timestamp = datetime.now().strftime('%Y%m%d')
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f'CMP-{timestamp}-{random_part}'


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home page - show landing page or redirect to dashboard"""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


# ==================== USER ROUTES ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing their complaints"""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    stats = {
        'total': len(complaints),
        'pending': len([c for c in complaints if c.status == 'pending']),
        'in_progress': len([c for c in complaints if c.status == 'in_progress']),
        'resolved': len([c for c in complaints if c.status == 'resolved'])
    }
    
    return render_template('dashboard.html', complaints=complaints, stats=stats)


@app.route('/submit-complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    """Submit new complaint page"""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    categories = Category.query.all()
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')
        location = request.form.get('location')
        
        # Validation
        if not title or not description or not category:
            flash('Title, description, and category are required', 'danger')
            return redirect(url_for('submit_complaint'))
        
        # Handle file upload
        attachment = None
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add unique identifier to filename
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                attachment = unique_filename
        
        # Generate tracking ID
        tracking_id = generate_tracking_id()
        
        # Create new complaint
        new_complaint = Complaint(
            tracking_id=tracking_id,
            user_id=current_user.id,
            title=title,
            description=description,
            category=category,
            priority=priority,
            location=location,
            attachment=attachment
        )
        
        try:
            db.session.add(new_complaint)
            db.session.commit()
            flash(f'Complaint submitted successfully! Your tracking ID is: {tracking_id}', 'success')
            return redirect(url_for('complaint_history'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('submit_complaint'))
    
    return render_template('submit_complaint.html', categories=categories)


@app.route('/complaint-history')
@login_required
def complaint_history():
    """View complaint history"""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('complaint_history.html', complaints=complaints)


@app.route('/track-complaint', methods=['GET', 'POST'])
@login_required
def track_complaint():
    """Track complaint by tracking ID"""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    complaint = None
    if request.method == 'POST':
        tracking_id = request.form.get('tracking_id')
        if tracking_id:
            complaint = Complaint.query.filter_by(tracking_id=tracking_id).first()
            if not complaint:
                flash('No complaint found with this tracking ID', 'warning')
    
    return render_template('complaint_detail.html', complaint=complaint)


@app.route('/complaint/<tracking_id>')
@login_required
def view_complaint(tracking_id):
    """View complaint details"""
    complaint = Complaint.query.filter_by(tracking_id=tracking_id).first_or_404()
    
    # Check permission (owner or admin)
    if complaint.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this complaint', 'danger')
        return redirect(url_for('dashboard'))
    
    notes = ComplaintNote.query.filter_by(complaint_id=complaint.id).order_by(ComplaintNote.created_at.desc()).all()
    return render_template('complaint_detail.html', complaint=complaint, notes=notes)


@app.route('/rate-complaint/<int:complaint_id>', methods=['POST'])
@login_required
def rate_complaint(complaint_id):
    """Rate a resolved complaint"""
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Check permission
    if complaint.user_id != current_user.id:
        flash('You do not have permission to rate this complaint', 'danger')
        return redirect(url_for('dashboard'))
    
    if complaint.status != 'resolved':
        flash('You can only rate resolved complaints', 'warning')
        return redirect(url_for('view_complaint', tracking_id=complaint.tracking_id))
    
    rating = request.form.get('rating')
    feedback = request.form.get('feedback')
    
    if rating:
        try:
            complaint.rating = int(rating)
            complaint.feedback = feedback
            db.session.commit()
            flash('Thank you for your feedback!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('view_complaint', tracking_id=complaint.tracking_id))


# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard showing all complaints and statistics"""
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    
    # Calculate statistics
    total = len(complaints)
    pending = len([c for c in complaints if c.status == 'pending'])
    in_progress = len([c for c in complaints if c.status == 'in_progress'])
    resolved = len([c for c in complaints if c.status == 'resolved'])
    
    # Priority counts
    urgent = len([c for c in complaints if c.priority == 'urgent'])
    high = len([c for c in complaints if c.priority == 'high'])
    
    # Recent complaints
    recent_complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(10).all()
    
    # Staff members (users who can be assigned complaints)
    staff = User.query.filter((User.role == 'admin') | (User.username.like('%staff%'))).all()
    
    stats = {
        'total': total,
        'pending': pending,
        'in_progress': in_progress,
        'resolved': resolved,
        'urgent': urgent,
        'high': high
    }
    
    return render_template('admin_dashboard.html', 
                           complaints=complaints, 
                           stats=stats, 
                           recent_complaints=recent_complaints,
                           staff=staff)


@app.route('/admin/complaints')
@login_required
@admin_required
def admin_complaints():
    """View all complaints with filtering options"""
    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    category_filter = request.args.get('category')
    
    query = Complaint.query
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)
    if category_filter:
        query = query.filter_by(category=category_filter)
    
    complaints = query.order_by(Complaint.created_at.desc()).all()
    categories = Category.query.all()
    staff = User.query.all()
    
    return render_template('admin_complaints.html', 
                           complaints=complaints, 
                           categories=categories,
                           staff=staff,
                           filters={'status': status_filter, 'priority': priority_filter, 'category': category_filter})


@app.route('/admin/update-complaint/<int:complaint_id>', methods=['POST'])
@login_required
@admin_required
def update_complaint(complaint_id):
    """Update complaint status and assignment"""
    complaint = Complaint.query.get_or_404(complaint_id)
    
    status = request.form.get('status')
    priority = request.form.get('priority')
    assigned_to = request.form.get('assigned_to')
    
    if status:
        complaint.status = status
    if priority:
        complaint.priority = priority
    if assigned_to:
        complaint.assigned_to = int(assigned_to) if assigned_to != 'None' else None
    
    try:
        db.session.commit()
        flash('Complaint updated successfully', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('view_complaint', tracking_id=complaint.tracking_id))


@app.route('/admin/add-note/<int:complaint_id>', methods=['POST'])
@login_required
@admin_required
def add_note(complaint_id):
    """Add internal note to complaint"""
    complaint = Complaint.query.get_or_404(complaint_id)
    note_content = request.form.get('note')
    
    if not note_content:
        flash('Note content is required', 'danger')
        return redirect(url_for('view_complaint', tracking_id=complaint.tracking_id))
    
    note = ComplaintNote(
        complaint_id=complaint.id,
        user_id=current_user.id,
        note=note_content
    )
    
    try:
        db.session.add(note)
        db.session.commit()
        flash('Note added successfully', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('view_complaint', tracking_id=complaint.tracking_id))


@app.route('/admin/categories', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_categories():
    """Manage complaint categories"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Category name is required', 'danger')
            return redirect(url_for('manage_categories'))
        
        # Check if category exists
        if Category.query.filter_by(name=name).first():
            flash('Category already exists', 'danger')
            return redirect(url_for('manage_categories'))
        
        category = Category(name=name, description=description)
        
        try:
            db.session.add(category)
            db.session.commit()
            flash('Category added successfully', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    
    categories = Category.query.order_by(Category.name).all()
    return render_template('admin_categories.html', categories=categories)


@app.route('/admin/delete-category/<int:category_id>')
@login_required
@admin_required
def delete_category(category_id):
    """Delete a category"""
    category = Category.query.get_or_404(category_id)
    
    try:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('manage_categories'))


# ==================== API ROUTES (JSON) ====================

@app.route('/api/register', methods=['POST'])
def api_register():
    """API endpoint for user registration"""
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password=hashed_password)
    
    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'Registration successful', 'user': user.to_dict()}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for user login"""
    data = request.get_json()
    
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'message': 'Login successful', 'user': user.to_dict()}), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/complaints', methods=['GET'])
@login_required
def api_complaints():
    """API endpoint to get all complaints"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    return jsonify({'complaints': [c.to_dict() for c in complaints]}), 200


@app.route('/api/complaints/user', methods=['GET'])
@login_required
def api_user_complaints():
    """API endpoint to get current user's complaints"""
    complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return jsonify({'complaints': [c.to_dict() for c in complaints]}), 200


@app.route('/api/categories', methods=['GET'])
def api_categories():
    """API endpoint to get all categories"""
    categories = Category.query.order_by(Category.name).all()
    return jsonify({'categories': [c.to_dict() for c in categories]}), 200


@app.route('/api/stats', methods=['GET'])
@login_required
@admin_required
def api_stats():
    """API endpoint to get dashboard statistics"""
    complaints = Complaint.query.all()
    
    stats = {
        'total': len(complaints),
        'pending': len([c for c in complaints if c.status == 'pending']),
        'in_progress': len([c for c in complaints if c.status == 'in_progress']),
        'resolved': len([c for c in complaints if c.status == 'resolved']),
        'urgent': len([c for c in complaints if c.priority == 'urgent']),
        'high': len([c for c in complaints if c.priority == 'high'])
    }
    
    return jsonify(stats), 200


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('error.html', error='Page not found', code=404), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('error.html', error='Internal server error', code=500), 500


# ==================== INITIALIZATION ====================

def create_default_categories():
    """Create default categories for the system"""
    default_categories = [
        ('Infrastructure', 'Issues related to buildings, roads, facilities'),
        ('Academic', 'Issues related to academic matters'),
        ('Administration', 'Issues related to administrative services'),
        ('IT Services', 'Issues related to computer and network services'),
        ('Hostel', 'Issues related to hostel facilities'),
        ('Cafeteria', 'Issues related to food and cafeteria'),
        ('Transportation', 'Issues related to transport services'),
        ('Security', 'Issues related to safety and security'),
        ('Other', 'Other miscellaneous issues')
    ]
    
    for name, description in default_categories:
        if not Category.query.filter_by(name=name).first():
            category = Category(name=name, description=description)
            db.session.add(category)
    
    db.session.commit()


def create_admin_user():
    """Create default admin user if not exists"""
    if not User.query.filter_by(email='admin@college.com').first():
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(
            username='admin',
            email='admin@college.com',
            password=hashed_password,
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin@college.com / admin123")

# Initialize database if running on Vercel
if os.environ.get('VERCEL') == '1':
    with app.app_context():
        try:
            db.create_all()
            create_default_categories()
            create_admin_user()
        except Exception as e:
            print(f"Database initialization error: {e}")

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
        create_default_categories()
        create_admin_user()
    
    # Run the application
    app.run(debug=True, host='127.0.0.1', port=5000)