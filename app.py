# Flask Mardi Gras Glossary Application
# File: app.py

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mardi_gras_glossary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    icon = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    terms = db.relationship('Term', backref='category_ref', lazy=True)
    
    def __repr__(self):
        return f'<Category {self.name}>'

class Term(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(100), unique=True, nullable=False)
    pronunciation = db.Column(db.String(100), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    etymology = db.Column(db.Text)
    example = db.Column(db.Text)
    difficulty = db.Column(db.String(20), nullable=False)  # tourist, local, expert
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_featured = db.Column(db.Boolean, default=False)
    view_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<Term {self.term}>'

class RelatedTerm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    term_id = db.Column(db.Integer, db.ForeignKey('term.id'), nullable=False)
    related_term_id = db.Column(db.Integer, db.ForeignKey('term.id'), nullable=False)
    
    # Relationships
    term = db.relationship('Term', foreign_keys=[term_id], backref='related_from')
    related_term = db.relationship('Term', foreign_keys=[related_term_id], backref='related_to')

class UserFavorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_ip = db.Column(db.String(45), nullable=False)  # Simple user identification
    term_id = db.Column(db.Integer, db.ForeignKey('term.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    term = db.relationship('Term', backref='favorites')

# Forms
class TermForm(FlaskForm):
    term = StringField('Term', validators=[DataRequired(), Length(min=1, max=100)])
    pronunciation = StringField('Pronunciation', validators=[DataRequired(), Length(min=1, max=100)])
    definition = TextAreaField('Definition', validators=[DataRequired(), Length(min=10, max=1000)])
    etymology = TextAreaField('Etymology', validators=[Length(max=500)])
    example = TextAreaField('Example', validators=[Length(max=500)])
    difficulty = SelectField('Difficulty Level', 
                            choices=[('tourist', 'Tourist'), ('local', 'Local'), ('expert', 'Expert')],
                            validators=[DataRequired()])
    category_id = SelectField('Category', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Term')

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(min=1, max=50)])
    icon = StringField('Icon (Emoji)', validators=[DataRequired(), Length(min=1, max=10)])
    description = TextAreaField('Description', validators=[Length(max=200)])
    submit = SubmitField('Add Category')

# Routes
@app.route('/')
def index():
    # Get featured term (word of the day)
    featured_term = Term.query.filter_by(is_featured=True).first()
    if not featured_term:
        featured_term = Term.query.order_by(db.func.random()).first()
    
    # Get statistics
    total_terms = Term.query.count()
    total_categories = Category.query.count()
    
    # Get recent terms
    recent_terms = Term.query.order_by(Term.created_at.desc()).limit(5).all()
    
    return render_template('index.html', 
                         featured_term=featured_term,
                         total_terms=total_terms,
                         total_categories=total_categories,
                         recent_terms=recent_terms)

@app.route('/glossary')
def glossary():
    # Get filter parameters
    category_filter = request.args.get('category', 'all')
    difficulty_filter = request.args.get('difficulty', 'all')
    search_query = request.args.get('search', '')
    
    # Build query
    query = Term.query
    
    if category_filter != 'all':
        category = Category.query.filter_by(name=category_filter).first()
        if category:
            query = query.filter_by(category_id=category.id)
    
    if difficulty_filter != 'all':
        query = query.filter_by(difficulty=difficulty_filter)
    
    if search_query:
        query = query.filter(
            db.or_(
                Term.term.contains(search_query),
                Term.definition.contains(search_query)
            )
        )
    
    # Get results
    terms = query.order_by(Term.term).all()
    categories = Category.query.all()
    
    return render_template('glossary.html', 
                         terms=terms, 
                         categories=categories,
                         current_category=category_filter,
                         current_difficulty=difficulty_filter,
                         search_query=search_query)

@app.route('/term/<int:term_id>')
def term_detail(term_id):
    term = Term.query.get_or_404(term_id)
    
    # Increment view count
    term.view_count += 1
    db.session.commit()
    
    # Get related terms
    related_term_ids = [rt.related_term_id for rt in RelatedTerm.query.filter_by(term_id=term_id).all()]
    related_terms = Term.query.filter(Term.id.in_(related_term_ids)).all() if related_term_ids else []
    
    return render_template('term_detail.html', term=term, related_terms=related_terms)

@app.route('/admin')
def admin():
    terms_count = Term.query.count()
    categories_count = Category.query.count()
    recent_terms = Term.query.order_by(Term.created_at.desc()).limit(10).all()
    popular_terms = Term.query.order_by(Term.view_count.desc()).limit(10).all()
    
    return render_template('admin.html',
                         terms_count=terms_count,
                         categories_count=categories_count,
                         recent_terms=recent_terms,
                         popular_terms=popular_terms)

@app.route('/admin/add_term', methods=['GET', 'POST'])
def add_term():
    form = TermForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        term = Term(
            term=form.term.data,
            pronunciation=form.pronunciation.data,
            definition=form.definition.data,
            etymology=form.etymology.data,
            example=form.example.data,
            difficulty=form.difficulty.data,
            category_id=form.category_id.data
        )
        db.session.add(term)
        db.session.commit()
        flash('Term added successfully!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('add_term.html', form=form)

@app.route('/admin/add_category', methods=['GET', 'POST'])
def add_category():
    form = CategoryForm()
    
    if form.validate_on_submit():
        category = Category(
            name=form.name.data,
            icon=form.icon.data,
            description=form.description.data
        )
        db.session.add(category)
        db.session.commit()
        flash('Category added successfully!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('add_category.html', form=form)

@app.route('/api/terms')
def api_terms():
    """API endpoint for terms (for AJAX requests)"""
    category = request.args.get('category', 'all')
    difficulty = request.args.get('difficulty', 'all')
    search = request.args.get('search', '')
    
    query = Term.query
    
    if category != 'all':
        cat = Category.query.filter_by(name=category).first()
        if cat:
            query = query.filter_by(category_id=cat.id)
    
    if difficulty != 'all':
        query = query.filter_by(difficulty=difficulty)
    
    if search:
        query = query.filter(
            db.or_(
                Term.term.contains(search),
                Term.definition.contains(search)
            )
        )
    
    terms = query.order_by(Term.term).all()
    
    return jsonify([{
        'id': t.id,
        'term': t.term,
        'pronunciation': t.pronunciation,
        'definition': t.definition,
        'category': t.category_ref.name,
        'difficulty': t.difficulty,
        'view_count': t.view_count
    } for t in terms])

@app.route('/api/random_term')
def api_random_term():
    """Get a random term for word of the day"""
    term = Term.query.order_by(db.func.random()).first()
    if term:
        return jsonify({
            'id': term.id,
            'term': term.term,
            'pronunciation': term.pronunciation,
            'definition': term.definition,
            'category': term.category_ref.name,
            'difficulty': term.difficulty
        })
    return jsonify({'error': 'No terms found'})

@app.route('/toggle_favorite/<int:term_id>')
def toggle_favorite(term_id):
    """Toggle favorite status for a term (simple IP-based tracking)"""
    user_ip = request.remote_addr
    existing_favorite = UserFavorite.query.filter_by(user_ip=user_ip, term_id=term_id).first()
    
    if existing_favorite:
        db.session.delete(existing_favorite)
        favorited = False
    else:
        favorite = UserFavorite(user_ip=user_ip, term_id=term_id)
        db.session.add(favorite)
        favorited = True
    
    db.session.commit()
    return jsonify({'favorited': favorited})

# Database initialization
def init_db():
    """Initialize database with seed data"""
    db.create_all()
    
    # Check if data already exists
    if Category.query.count() > 0:
        return
    
    # Seed categories
    categories_data = [
        {'name': 'Core Terms', 'icon': '⭐', 'description': 'Essential Carnival vocabulary'},
        {'name': 'Krewes', 'icon': '👑', 'description': 'Carnival organizations and societies'},
        {'name': 'Food & Drink', 'icon': '🎂', 'description': 'Traditional Carnival cuisine'},
        {'name': 'Throws', 'icon': '📿', 'description': 'Items thrown from parade floats'},
        {'name': 'Parades', 'icon': '🎪', 'description': 'Parade terminology and logistics'},
        {'name': 'Music & Culture', 'icon': '🎵', 'description': 'Musical traditions and performances'},
        {'name': 'Local Slang', 'icon': '💬', 'description': 'New Orleans expressions and dialect'},
        {'name': 'Culture', 'icon': '🎨', 'description': 'Cultural traditions and practices'},
        {'name': 'Locations', 'icon': '📍', 'description': 'Important Carnival venues and routes'},
        {'name': 'Viewing', 'icon': '👀', 'description': 'Parade watching and etiquette'},
        {'name': 'Balls & Events', 'icon': '🎩', 'description': 'Formal Carnival celebrations'},
        {'name': 'Royalty & Titles', 'icon': '👑', 'description': 'Carnival hierarchy and honors'},
        {'name': 'Regional', 'icon': '🌎', 'description': 'Carnival celebrations across the region'},
        {'name': 'Tourism', 'icon': '✈️', 'description': 'Visitor information and services'},
        {'name': 'Seasonal', 'icon': '📅', 'description': 'Carnival calendar and timing'},
        {'name': 'Historical', 'icon': '📜', 'description': 'Carnival history and evolution'}
    ]
    
    for cat_data in categories_data:
        category = Category(**cat_data)
        db.session.add(category)
    
    db.session.commit()
    
    print("Database initialized with categories!")
    print("Run 'python seed_data.py' to load the full glossary terms.")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)