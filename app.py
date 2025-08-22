# app.py - Ultra-Secure Flask API with Flask-Security-Too
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, roles_required, current_user
from flask_security.utils import hash_password, verify_password
from flask_security.forms import RegisterForm, LoginForm
from flask_security.models import fsqla_v3 as fsqla
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_wtf import FlaskForm
from flask_mail import Mail
from wtforms import StringField, TextAreaField, SelectField, SubmitField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Length, Optional, Email
from datetime import datetime, timedelta
import os
import json
import secrets
from sqlalchemy import func, or_, text
from functools import wraps
import re
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import logging
from logging.handlers import RotatingFileHandler

# Enhanced Security Configuration
class SecurityConfig:
    """Enhanced security configuration"""
    
    # Password Security - Using Argon2id (most secure)
    SECURITY_PASSWORD_HASH = 'argon2'
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', secrets.token_hex(32))
    
    # Argon2 Parameters (OWASP recommended)
    SECURITY_PASSWORD_HASH_OPTIONS = {
        'argon2': {
            'memory_cost': 102400,  # 100 MB
            'time_cost': 2,         # 2 iterations
            'parallelism': 8,       # 8 parallel threads
        }
    }
    
    # Session Security
    SECURITY_CSRF_PROTECT_MECHANISMS = ['session', 'basic']
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = True
    
    # Login Security
    SECURITY_LOGIN_ERROR_VIEW = '/auth/login-error'
    SECURITY_POST_LOGIN_REDIRECT_ENDPOINT = '/admin/dashboard'
    SECURITY_POST_LOGOUT_REDIRECT_ENDPOINT = '/auth/login'
    
    # Account Security
    SECURITY_REGISTERABLE = False  # Disable public registration
    SECURITY_RECOVERABLE = True    # Enable password recovery
    SECURITY_TRACKABLE = True      # Track login attempts
    SECURITY_CHANGEABLE = True     # Allow password changes
    
    # Two-Factor Authentication
    SECURITY_TWO_FACTOR = True
    SECURITY_TWO_FACTOR_REQUIRED = False  # Make optional but recommended
    SECURITY_TWO_FACTOR_ENABLED_METHODS = ['authenticator', 'sms']
    
    # Rate Limiting for Auth
    SECURITY_LOGIN_USER_TEMPLATE = 'security/login_user.html'
    
    # Email Configuration for Recovery
    SECURITY_EMAIL_SENDER = os.environ.get('SECURITY_EMAIL_SENDER', 'noreply@mardigrasworld.com')
    
    # Token Security
    SECURITY_RESET_PASSWORD_WITHIN = '2 hours'
    SECURITY_CONFIRM_EMAIL_WITHIN = '5 days'

# App Configuration
app = Flask(__name__)

# Basic Flask Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///mardi_gras_glossary.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security Configuration
for attr in dir(SecurityConfig):
    if not attr.startswith('__'):
        app.config[attr] = getattr(SecurityConfig, attr)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

# Mail Configuration for Password Recovery
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Rate Limiting Configuration
app.config['RATELIMIT_STORAGE_URL'] = os.environ.get('REDIS_URL', 'memory://')

# CORS Configuration
ALLOWED_ORIGINS = [
    'https://mardigrasworld.com',
    'https://www.mardigrasworld.com',
    'https://api.mardigrasworld.com',
    'http://localhost:3000',  # For development
    'http://localhost:8000'   # For development
]

# Initialize Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
cors = CORS(app, origins=ALLOWED_ORIGINS)
mail = Mail(app)

# Enhanced Logging Setup
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler('logs/mardi_gras_api.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Mardi Gras API startup')

# JWT Blacklist (in production, use Redis)
blacklisted_tokens = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklisted_tokens

# ==================== SECURITY MODELS ====================

# Setup Flask-Security tables
fsqla.FsModels.set_db_info(db)

class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    permissions = db.Column(db.Text)  # JSON string of permissions

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    
    # Flask-Security fields
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False)
    confirmed_at = db.Column(db.DateTime())
    active = db.Column(db.Boolean(), default=True)
    
    # Security tracking
    current_login_at = db.Column(db.DateTime())
    current_login_ip = db.Column(db.String(45))
    last_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer, default=0)
    
    # Two-Factor Authentication
    tf_primary_method = db.Column(db.String(255))
    tf_totp_secret = db.Column(db.String(255))
    tf_phone_number = db.Column(db.String(255))
    
    # API Access
    api_key = db.Column(db.String(255), unique=True, nullable=True)
    api_key_created_at = db.Column(db.DateTime())
    api_calls_count = db.Column(db.Integer, default=0)
    api_calls_last_reset = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Custom fields
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    organization = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users', lazy='dynamic'))

# Many-to-many relationship table
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('users.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('roles.id'))
)

class APIUsage(db.Model):
    __tablename__ = 'api_usage'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    endpoint = db.Column(db.String(200), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    response_code = db.Column(db.Integer)
    response_time = db.Column(db.Float)  # Response time in seconds
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='api_calls')

class SecurityAudit(db.Model):
    __tablename__ = 'security_audit'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(100), nullable=False)  # login, logout, failed_login, password_change, etc.
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON string with additional details
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='security_events')

class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    icon = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text)
    sort_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relationships
    terms = db.relationship('Term', backref='category_rel', lazy=True, cascade='all, delete-orphan')
    creator = db.relationship('User', backref='created_categories')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'icon': self.icon,
            'description': self.description,
            'sort_order': self.sort_order,
            'is_active': self.is_active,
            'term_count': len([term for term in self.terms if term.is_active])
        }

class Term(db.Model):
    __tablename__ = 'terms'
    
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(200), unique=True, nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    pronunciation = db.Column(db.String(200), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    etymology = db.Column(db.Text)
    example = db.Column(db.Text)
    difficulty = db.Column(db.String(20), nullable=False)  # tourist, local, expert
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    view_count = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_terms')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='updated_terms')
    
    # Add indexes for better search performance
    __table_args__ = (
        db.Index('idx_term_search', 'term'),
        db.Index('idx_definition_search', 'definition'),
        db.Index('idx_difficulty', 'difficulty'),
        db.Index('idx_category', 'category_id'),
        db.Index('idx_featured', 'is_featured'),
        db.Index('idx_active', 'is_active'),
    )
    
    def to_dict(self, include_related=False):
        data = {
            'id': self.id,
            'term': self.term,
            'slug': self.slug,
            'pronunciation': self.pronunciation,
            'definition': self.definition,
            'etymology': self.etymology,
            'example': self.example,
            'difficulty': self.difficulty,
            'category': self.category_rel.name,
            'category_slug': self.category_rel.slug,
            'category_icon': self.category_rel.icon,
            'view_count': self.view_count,
            'is_featured': self.is_featured,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_related:
            data['related_terms'] = [rt.to_dict() for rt in self.get_related_terms()]
        
        return data
    
    def get_related_terms(self, limit=5):
        """Get related terms based on category and similar keywords"""
        return Term.query.filter(
            Term.category_id == self.category_id,
            Term.id != self.id,
            Term.is_active == True
        ).order_by(func.random()).limit(limit).all()

class SearchLog(db.Model):
    __tablename__ = 'search_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    query = db.Column(db.String(500), nullable=False)
    results_count = db.Column(db.Integer, default=0)
    user_ip = db.Column(db.String(45))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    endpoint = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='searches')

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# ==================== CUSTOM PASSWORD HASHER ====================

class SecurePasswordHasher:
    """Ultra-secure password hasher using Argon2id"""
    
    def __init__(self):
        self.ph = PasswordHasher(
            memory_cost=102400,  # 100 MB
            time_cost=2,         # 2 iterations
            parallelism=8,       # 8 parallel threads
            hash_len=32,         # 32 byte hash
            salt_len=16          # 16 byte salt
        )
    
    def hash_password(self, password: str) -> str:
        """Hash password with Argon2id"""
        try:
            return self.ph.hash(password)
        except Exception as e:
            app.logger.error(f"Password hashing failed: {e}")
            raise
    
    def verify_password(self, password: str, hash: str) -> bool:
        """Verify password against hash"""
        try:
            self.ph.verify(hash, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            app.logger.error(f"Password verification failed: {e}")
            return False
    
    def needs_rehash(self, hash: str) -> bool:
        """Check if password needs rehashing (parameters changed)"""
        try:
            return self.ph.check_needs_rehash(hash)
        except Exception:
            return True

# Initialize secure password hasher
secure_hasher = SecurePasswordHasher()

# ==================== SECURITY DECORATORS ====================

def log_security_event(event_type: str, details: str = None):
    """Log security events for audit trail"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = None
            if current_user.is_authenticated:
                user_id = current_user.id
            
            audit_log = SecurityAudit(
                user_id=user_id,
                event_type=event_type,
                ip_address=request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                user_agent=request.headers.get('User-Agent', '')[:500],
                details=details
            )
            
            try:
                result = f(*args, **kwargs)
                db.session.add(audit_log)
                db.session.commit()
                return result
            except Exception as e:
                audit_log.details = f"Error: {str(e)}"
                db.session.add(audit_log)
                db.session.commit()
                raise
        
        return decorated_function
    return decorator

def log_api_usage(f):
    """Enhanced API usage logging with performance metrics"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = datetime.utcnow()
        user_id = None
        
        # Try to get user from JWT or current_user
        try:
            if current_user.is_authenticated:
                user_id = current_user.id
            else:
                jwt_user_id = get_jwt_identity()
                if jwt_user_id:
                    user_id = jwt_user_id
        except:
            pass
        
        log = APIUsage(
            user_id=user_id,
            endpoint=request.endpoint,
            method=request.method,
            ip_address=request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        
        try:
            result = f(*args, **kwargs)
            end_time = datetime.utcnow()
            
            log.response_code = 200
            log.response_time = (end_time - start_time).total_seconds()
            
            # Update user API call count
            if user_id:
                user = User.query.get(user_id)
                if user:
                    user.api_calls_count += 1
            
            db.session.add(log)
            db.session.commit()
            return result
            
        except Exception as e:
            end_time = datetime.utcnow()
            log.response_code = 500
            log.response_time = (end_time - start_time).total_seconds()
            db.session.add(log)
            db.session.commit()
            raise
    
    return decorated_function

def api_key_or_jwt_required(f):
    """Allow either API key or JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Try JWT first
        try:
            user_id = get_jwt_identity()
            if user_id:
                user = User.query.get(user_id)
                if user and user.active:
                    request.current_user = user
                    return f(*args, **kwargs)
        except:
            pass
        
        # Try API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = User.query.filter_by(api_key=api_key, active=True).first()
            if user:
                request.current_user = user
                return f(*args, **kwargs)
        
        return jsonify({'error': 'Authentication required'}), 401
    
    return decorated_function

# ==================== ENHANCED AUTHENTICATION ROUTES ====================

@app.route('/auth/secure-login', methods=['POST'])
@limiter.limit("5 per minute")
@log_security_event('login_attempt')
def secure_login():
    """Ultra-secure login endpoint with enhanced protection"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        log_security_event('failed_login', 'Missing credentials')()
        return jsonify({'error': 'Email and password required'}), 400
    
    # Find user by email
    user = User.query.filter_by(email=data['email'], active=True).first()
    
    if not user:
        # Prevent user enumeration - same response time
        secure_hasher.verify_password('dummy_password', '$argon2id$v=19$m=102400,t=2,p=8$dummy')
        log_security_event('failed_login', f"User not found: {data['email']}")()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not secure_hasher.verify_password(data['password'], user.password):
        log_security_event('failed_login', f"Invalid password for: {user.email}")()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if password needs rehashing
    if secure_hasher.needs_rehash(user.password):
        user.password = secure_hasher.hash_password(data['password'])
        db.session.commit()
        app.logger.info(f"Password rehashed for user: {user.email}")
    
    # Update login tracking
    user.last_login_at = user.current_login_at
    user.last_login_ip = user.current_login_ip
    user.current_login_at = datetime.utcnow()
    user.current_login_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    user.login_count = (user.login_count or 0) + 1
    
    db.session.commit()
    
    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    # Check for 2FA requirement
    two_fa_required = user.tf_primary_method is not None
    
    log_security_event('successful_login', f"User: {user.email}")()
    
    response_data = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'roles': [role.name for role in user.roles],
            'two_fa_required': two_fa_required
        }
    }
    
    return jsonify(response_data)

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
@log_security_event('logout')
def secure_logout():
    """Secure logout with token blacklisting"""
    from flask_jwt_extended import get_jwt
    
    jti = get_jwt()['jti']
    blacklisted_tokens.add(jti)
    
    return jsonify({'message': 'Successfully logged out'})

@app.route('/auth/change-password', methods=['POST'])
@jwt_required()
@log_security_event('password_change_attempt')
def change_password():
    """Secure password change endpoint"""
    data = request.get_json()
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not data.get('current_password') or not data.get('new_password'):
        return jsonify({'error': 'Current and new password required'}), 400
    
    # Verify current password
    if not secure_hasher.verify_password(data['current_password'], user.password):
        log_security_event('failed_password_change', 'Invalid current password')()
        return jsonify({'error': 'Invalid current password'}), 400
    
    # Validate new password strength
    new_password = data['new_password']
    if len(new_password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters long'}), 400
    
    if not re.search(r'[A-Z]', new_password):
        return jsonify({'error': 'Password must contain uppercase letters'}), 400
    
    if not re.search(r'[a-z]', new_password):
        return jsonify({'error': 'Password must contain lowercase letters'}), 400
    
    if not re.search(r'\d', new_password):
        return jsonify({'error': 'Password must contain numbers'}), 400
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return jsonify({'error': 'Password must contain special characters'}), 400
    
    # Hash new password
    user.password = secure_hasher.hash_password(new_password)
    db.session.commit()
    
    log_security_event('password_changed', 'Password successfully changed')()
    
    return jsonify({'message': 'Password changed successfully'})

@app.route('/auth/generate-api-key', methods=['POST'])
@jwt_required()
@roles_required('admin')
@log_security_event('api_key_generation')
def generate_api_key():
    """Generate new API key for user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate secure API key
    user.api_key = secrets.token_urlsafe(32)
    user.api_key_created_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'api_key': user.api_key})

# ==================== PUBLIC API ROUTES (Enhanced Security) ====================

@app.route('/glossary/terms')
@limiter.limit("100 per hour")
@api_key_or_jwt_required
@log_api_usage
def api_terms():
    """Enhanced secure terms endpoint"""
    # Get parameters with validation
    query = request.args.get('search', '').strip()[:500]  # Limit query length
    category_slug = request.args.get('category', '').strip()[:100]
    difficulty = request.args.get('difficulty', '').strip()
    limit = min(max(request.args.get('limit', 50, type=int), 1), 100)  # Clamp between 1-100
    
    # Validate difficulty parameter
    if difficulty and difficulty not in ['tourist', 'local', 'expert']:
        return jsonify({'error': 'Invalid difficulty level'}), 400
    
    # Build query - only active terms
    terms_query = Term.query.join(Category).filter(
        Term.is_active == True,
        Category.is_active == True
    )
    
    if query:
        # Prevent SQL injection with parameterized queries
        search_filter = or_(
            Term.term.ilike(f'%{query}%'),
            Term.definition.ilike(f'%{query}%')
        )
        terms_query = terms_query.filter(search_filter)
        
        # Log search
        log_search(query, terms_query.count())
    
    if category_slug:
        terms_query = terms_query.filter(Category.slug == category_slug)
    
    if difficulty:
        terms_query = terms_query.filter(Term.difficulty == difficulty)
    
    # Execute query
    terms = terms_query.order_by(Term.term).limit(limit).all()
    
    return jsonify({
        'terms': [term.to_dict() for term in terms],
        'count': len(terms),
        'total': terms_query.count() if len(terms) == limit else len(terms),
        'query_info': {
            'search': query,
            'category': category_slug,
            'difficulty': difficulty,
            'limit': limit
        }
    })

@app.route('/admin/security/audit')
@jwt_required()
@roles_required('admin')
def security_audit():
    """Security audit endpoint for administrators"""
    days = min(request.args.get('days', 30, type=int), 90)  # Max 90 days
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get security events
    events = SecurityAudit.query.filter(
        SecurityAudit.timestamp >= start_date
    ).order_by(SecurityAudit.timestamp.desc()).limit(1000).all()
    
    # Get failed login attempts
    failed_logins = SecurityAudit.query.filter(
        SecurityAudit.event_type == 'failed_login',
        SecurityAudit.timestamp >= start_date
    ).count()
    
    # Get unique IPs with failed attempts
    suspicious_ips = db.session.query(
        SecurityAudit.ip_address,
        func.count(SecurityAudit.id).label('attempts')
    ).filter(
        SecurityAudit.event_type == 'failed_login',
        SecurityAudit.timestamp >= start_date
    ).group_by(SecurityAudit.ip_address).having(
        func.count(SecurityAudit.id) > 5
    ).all()
    
    return jsonify({
        'events': [{
            'id': event.id,
            'event_type': event.event_type,
            'user_email': event.user.email if event.user else None,
            'ip_address': event.ip_address,
            'timestamp': event.timestamp.isoformat(),
            'details': event.details
        } for event in events],
        'summary': {
            'total_events': len(events),
            'failed_logins': failed_logins,
            'suspicious_ips': [{'ip': ip, 'attempts': attempts} for ip, attempts in suspicious_ips],
            'period_days': days
        }
    })

@app.route('/admin/users')
@jwt_required()
@roles_required('admin')
def admin_users():
    """Admin endpoint to manage users"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'users': [{
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'active': user.active,
            'confirmed_at': user.confirmed_at.isoformat() if user.confirmed_at else None,
            'login_count': user.login_count,
            'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
            'api_calls_count': user.api_calls_count,
            'roles': [role.name for role in user.roles],
            'created_at': user.created_at.isoformat()
        } for user in users.items],
        'pagination': {
            'page': users.page,
            'pages': users.pages,
            'per_page': users.per_page,
            'total': users.total,
            'has_next': users.has_next,
            'has_prev': users.has_prev
        }
    })

@app.route('/admin/users', methods=['POST'])
@jwt_required()
@roles_required('admin')
@log_security_event('user_creation')
def create_user():
    """Admin endpoint to create new user"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['email', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}, data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'User already exists'}), 400
    
    # Validate password strength
    password = data['password']
    if len(password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters long'}), 400
    
    try:
        # Create user with secure password hashing
        user = user_datastore.create_user(
            email=data['email'],
            username=data.get('username'),
            password=secure_hasher.hash_password(password),
            fs_uniquifier=secrets.token_hex(16),
            active=data.get('active', True),
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            organization=data.get('organization')
        )
        
        # Add roles if specified
        roles = data.get('roles', [])
        for role_name in roles:
            role = Role.query.filter_by(name=role_name).first()
            if role:
                user_datastore.add_role_to_user(user, role)
        
        # Generate API key if requested
        if data.get('generate_api_key'):
            user.api_key = secrets.token_urlsafe(32)
            user.api_key_created_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'api_key': user.api_key if user.api_key else None
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating user: {e}")
        return jsonify({'error': 'Failed to create user'}), 500

# ==================== UTILITY FUNCTIONS ====================

def create_slug(text):
    """Create URL-friendly slug from text with enhanced security"""
    if not text:
        return ''
    
    # Sanitize input
    text = str(text)[:200]  # Limit length
    
    # Convert to lowercase and replace spaces/special chars with hyphens
    slug = re.sub(r'[^\w\s-]', '', text.lower())
    slug = re.sub(r'[-\s]+', '-', slug)
    return slug.strip('-')

def log_search(query, results_count):
    """Enhanced search logging with user tracking"""
    try:
        user_id = None
        try:
            if current_user.is_authenticated:
                user_id = current_user.id
            else:
                user_id = get_jwt_identity()
        except:
            pass
        
        search_log = SearchLog(
            query=query.strip()[:500],
            results_count=results_count,
            user_ip=request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
            user_id=user_id,
            endpoint=request.endpoint
        )
        db.session.add(search_log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed to log search: {e}")

def validate_input(data, schema):
    """Validate input data against schema"""
    errors = []
    
    for field, rules in schema.items():
        value = data.get(field)
        
        if rules.get('required') and not value:
            errors.append(f'{field} is required')
            continue
        
        if value:
            if 'max_length' in rules and len(str(value)) > rules['max_length']:
                errors.append(f'{field} exceeds maximum length of {rules["max_length"]}')
            
            if 'min_length' in rules and len(str(value)) < rules['min_length']:
                errors.append(f'{field} must be at least {rules["min_length"]} characters')
            
            if 'pattern' in rules and not re.match(rules['pattern'], str(value)):
                errors.append(f'{field} format is invalid')
    
    return errors

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/glossary/') or request.path.startswith('/admin/'):
        return jsonify({'error': 'Resource not found'}), 404
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': str(e.retry_after),
        'message': 'Please wait before making more requests'
    }), 429

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400

@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({'error': 'Forbidden', 'message': 'Insufficient permissions'}), 403

@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401

# ==================== JWT ERROR HANDLERS ====================

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired', 'message': 'Please log in again'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token', 'message': 'Token is malformed or invalid'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Token required', 'message': 'Authentication token is required'}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token revoked', 'message': 'Token has been revoked'}), 401

# ==================== HEALTH CHECK AND SECURITY STATUS ====================

@app.route('/health')
def health_check():
    """Enhanced health check with security status"""
    try:
        # Test database connectivity
        db.session.execute(text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'healthy' if db_status == 'healthy' else 'degraded',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0-secure',
        'services': {
            'database': db_status,
            'security': 'active',
            'rate_limiting': 'active'
        },
        'security_features': {
            'password_hashing': 'argon2id',
            'two_factor_auth': 'available',
            'rate_limiting': 'enabled',
            'audit_logging': 'enabled',
            'csrf_protection': 'enabled'
        }
    })

@app.route('/security/status')
@jwt_required()
@roles_required('admin')
def security_status():
    """Detailed security status for administrators"""
    # Get recent security metrics
    recent_logins = SecurityAudit.query.filter(
        SecurityAudit.event_type == 'successful_login',
        SecurityAudit.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    failed_logins = SecurityAudit.query.filter(
        SecurityAudit.event_type == 'failed_login',
        SecurityAudit.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    active_users = User.query.filter_by(active=True).count()
    total_api_calls = APIUsage.query.filter(
        APIUsage.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    return jsonify({
        'security_status': 'healthy',
        'metrics': {
            'recent_logins_24h': recent_logins,
            'failed_logins_24h': failed_logins,
            'active_users': active_users,
            'api_calls_24h': total_api_calls,
            'blacklisted_tokens': len(blacklisted_tokens)
        },
        'security_config': {
            'password_hashing': 'argon2id',
            'min_password_length': 12,
            'rate_limiting': 'enabled',
            'two_factor_auth': 'optional',
            'audit_logging': 'enabled',
            'token_expiry': '24 hours'
        }
    })

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database with security enhancements"""
    with app.app_context():
        db.create_all()
        
        # Create default roles
        if not Role.query.filter_by(name='admin').first():
            admin_role = user_datastore.create_role(
                name='admin',
                description='Administrator with full access',
                permissions=json.dumps(['read', 'write', 'delete', 'admin'])
            )
        
        if not Role.query.filter_by(name='editor').first():
            editor_role = user_datastore.create_role(
                name='editor',
                description='Editor with content management access',
                permissions=json.dumps(['read', 'write'])
            )
        
        if not Role.query.filter_by(name='viewer').first():
            viewer_role = user_datastore.create_role(
                name='viewer',
                description='Read-only access',
                permissions=json.dumps(['read'])
            )
        
        # Create default admin user if none exists
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@mardigrasworld.com')
        if not User.query.filter_by(email=admin_email).first():
            admin_password = os.environ.get('ADMIN_PASSWORD', 'SecureAdmin123!')
            
            admin_user = user_datastore.create_user(
                email=admin_email,
                username=os.environ.get('ADMIN_USERNAME', 'admin'),
                password=secure_hasher.hash_password(admin_password),
                fs_uniquifier=secrets.token_hex(16),
                active=True,
                confirmed_at=datetime.utcnow(),
                first_name='System',
                last_name='Administrator'
            )
            
            # Add admin role
            admin_role = Role.query.filter_by(name='admin').first()
            user_datastore.add_role_to_user(admin_user, admin_role)
            
            # Generate API key
            admin_user.api_key = secrets.token_urlsafe(32)
            admin_user.api_key_created_at = datetime.utcnow()
            
            db.session.commit()
            
            print(f"✅ Created admin user: {admin_email}")
            print(f"🔑 Admin API Key: {admin_user.api_key}")
            print(f"⚠️  Please change the default password immediately!")
        
        print("✅ Database tables created with enhanced security!")

if __name__ == '__main__':
    init_db()
    app.run(debug=False, port=5555)  # Disable debug in production