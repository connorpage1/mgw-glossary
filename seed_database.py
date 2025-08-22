# seed_database.py - Database seeding script
import json
import os
from app import app, db, Category, Term, create_slug

def seed_categories():
    """Seed categories from predefined data"""
    categories_data = [
        {'name': 'Core Terms', 'icon': '⭐', 'description': 'Essential Carnival vocabulary', 'sort_order': 1},
        {'name': 'Krewes', 'icon': '👑', 'description': 'Carnival organizations and societies', 'sort_order': 2},
        {'name': 'Food & Drink', 'icon': '🎂', 'description': 'Traditional Carnival cuisine', 'sort_order': 3},
        {'name': 'Throws', 'icon': '📿', 'description': 'Items thrown from parade floats', 'sort_order': 4},
        {'name': 'Parades', 'icon': '🎪', 'description': 'Parade terminology and logistics', 'sort_order': 5},
        {'name': 'Music & Culture', 'icon': '🎵', 'description': 'Musical traditions and performances', 'sort_order': 6},
        {'name': 'Local Slang', 'icon': '💬', 'description': 'New Orleans expressions and dialect', 'sort_order': 7},
        {'name': 'Culture', 'icon': '🎨', 'description': 'Cultural traditions and practices', 'sort_order': 8},
        {'name': 'Locations', 'icon': '📍', 'description': 'Important Carnival venues and routes', 'sort_order': 9},
        {'name': 'Viewing', 'icon': '👀', 'description': 'Parade watching and etiquette', 'sort_order': 10},
        {'name': 'Balls & Events', 'icon': '🎩', 'description': 'Formal Carnival celebrations', 'sort_order': 11},
        {'name': 'Royalty & Titles', 'icon': '👑', 'description': 'Carnival hierarchy and honors', 'sort_order': 12},
        {'name': 'Regional', 'icon': '🌎', 'description': 'Carnival celebrations across the region', 'sort_order': 13},
        {'name': 'Tourism', 'icon': '✈️', 'description': 'Visitor information and services', 'sort_order': 14},
        {'name': 'Seasonal', 'icon': '📅', 'description': 'Carnival calendar and timing', 'sort_order': 15},
        {'name': 'Historical', 'icon': '📜', 'description': 'Carnival history and evolution', 'sort_order': 16}
    ]
    
    category_map = {}
    
    for cat_data in categories_data:
        # Check if category exists
        existing = Category.query.filter_by(name=cat_data['name']).first()
        if existing:
            category_map[cat_data['name']] = existing.id
            continue
            
        # Create new category
        category = Category(
            name=cat_data['name'],
            slug=create_slug(cat_data['name']),
            icon=cat_data['icon'],
            description=cat_data['description'],
            sort_order=cat_data['sort_order']
        )
        db.session.add(category)
        db.session.flush()  # Get the ID
        category_map[cat_data['name']] = category.id
    
    db.session.commit()
    print(f"✅ Seeded {len(categories_data)} categories")
    return category_map

def seed_terms_from_json(json_file_path):
    """Seed terms from JSON file"""
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ JSON file not found: {json_file_path}")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in {json_file_path}: {e}")
        return
    
    # Get category mapping
    category_map = {cat.name: cat.id for cat in Category.query.all()}
    
    terms_added = 0
    terms_updated = 0
    
    for term_data in data.get('terms', []):
        # Check if term exists
        existing_term = Term.query.filter_by(term=term_data['term']).first()
        
        # Get category ID
        category_id = category_map.get(term_data['category'])
        if not category_id:
            print(f"⚠️  Category not found for term '{term_data['term']}': {term_data['category']}")
            continue
        
        if existing_term:
            # Update existing term
            existing_term.pronunciation = term_data['pronunciation']
            existing_term.definition = term_data['definition']
            existing_term.etymology = term_data.get('etymology', '')
            existing_term.example = term_data.get('example', '')
            existing_term.difficulty = term_data['difficulty']
            existing_term.category_id = category_id
            existing_term.updated_at = db.func.now()
            terms_updated += 1
        else:
            # Create new term
            term = Term(
                term=term_data['term'],
                slug=create_slug(term_data['term']),
                pronunciation=term_data['pronunciation'],
                definition=term_data['definition'],
                etymology=term_data.get('etymology', ''),
                example=term_data.get('example', ''),
                difficulty=term_data['difficulty'],
                category_id=category_id
            )
            db.session.add(term)
            terms_added += 1
    
    try:
        db.session.commit()
        print(f"✅ Added {terms_added} new terms")
        print(f"✅ Updated {terms_updated} existing terms")
        
        # Set a random featured term if none exists
        if not Term.query.filter_by(is_featured=True).first():
            random_term = Term.query.order_by(db.func.random()).first()
            if random_term:
                random_term.is_featured = True
                db.session.commit()
                print(f"✅ Set featured term: {random_term.term}")
                
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error saving terms: {e}")

def seed_sample_data():
    """Seed some sample data for testing"""
    sample_terms = [
        {
            'term': 'Mardi Gras',
            'pronunciation': 'MAR-dee GRAH',
            'category': 'Core Terms',
            'difficulty': 'tourist',
            'definition': 'French for "Fat Tuesday," the culminating day of Carnival season before Ash Wednesday and the start of Lent.',
            'etymology': 'From French "mardi" (Tuesday) and "gras" (fat)',
            'example': 'Mardi Gras is celebrated with parades, balls, and feasting before the fasting period of Lent begins.'
        },
        {
            'term': 'Krewe',
            'pronunciation': 'KROO',
            'category': 'Core Terms',
            'difficulty': 'tourist',
            'definition': 'An organized group that puts on a parade or ball during Carnival season. Each krewe has its own theme, colors, and traditions.',
            'etymology': 'Intentional misspelling of "crew" popularized by the Krewe of Comus in 1857',
            'example': 'The Krewe of Rex is known as the "King of Carnival" and parades on Mardi Gras day.'
        },
        {
            'term': 'King Cake',
            'pronunciation': 'KING KAYK',
            'category': 'Food & Drink',
            'difficulty': 'tourist',
            'definition': 'A traditional oval-shaped cake decorated in purple, gold, and green with a small plastic baby hidden inside. Eaten during Carnival season.',
            'etymology': 'Named for the Biblical three kings; tradition dates to 12th century France',
            'example': 'Whoever finds the baby in the king cake is supposed to host the next party and buy the next cake.'
        },
        {
            'term': 'Throws',
            'pronunciation': 'THROHZ',
            'category': 'Throws',
            'difficulty': 'tourist',
            'definition': 'Items tossed from parade floats to spectators, including beads, doubloons, cups, and specialty items.',
            'etymology': 'From the practice of throwing trinkets to crowds, dating to 1870s',
            'example': 'Popular throws include plastic beads, aluminum doubloons, and decorated cups.'
        },
        {
            'term': 'Rex',
            'pronunciation': 'REKS',
            'category': 'Krewes',
            'difficulty': 'tourist',
            'definition': 'The "King of Carnival," this prestigious krewe parades on Mardi Gras day and established many Carnival traditions.',
            'etymology': 'Latin for "king"; krewe founded in 1872',
            'example': 'Rex established the official Carnival colors of purple, gold, and green.'
        }
    ]
    
    # Get category mapping
    category_map = {cat.name: cat.id for cat in Category.query.all()}
    
    for term_data in sample_terms:
        # Check if term already exists
        if Term.query.filter_by(term=term_data['term']).first():
            continue
            
        category_id = category_map.get(term_data['category'])
        if not category_id:
            continue
            
        term = Term(
            term=term_data['term'],
            slug=create_slug(term_data['term']),
            pronunciation=term_data['pronunciation'],
            definition=term_data['definition'],
            etymology=term_data.get('etymology', ''),
            example=term_data.get('example', ''),
            difficulty=term_data['difficulty'],
            category_id=category_id
        )
        db.session.add(term)
    
    db.session.commit()
    print("✅ Added sample terms")

def main():
    """Main seeding function"""
    with app.app_context():
        print("🚀 Starting database seeding...")
        
        # Create tables if they don't exist
        db.create_all()
        print("✅ Database tables ready")
        
        # Seed categories first
        category_map = seed_categories()
        
        # Try to seed from JSON file
        json_file = 'mardi_gras_glossary_data.json'
        if os.path.exists(json_file):
            print(f"📁 Loading terms from {json_file}")
            seed_terms_from_json(json_file)
        else:
            print(f"⚠️  {json_file} not found, using sample data")
            seed_sample_data()
        
        # Print final statistics
        total_terms = Term.query.count()
        total_categories = Category.query.count()
        
        print(f"\n🎉 Seeding complete!")
        print(f"📊 Final counts:")
        print(f"   📚 Categories: {total_categories}")
        print(f"   📖 Terms: {total_terms}")
        
        if total_terms > 0:
            print(f"\n📈 Breakdown by difficulty:")
            for difficulty in ['tourist', 'local', 'expert']:
                count = Term.query.filter_by(difficulty=difficulty).count()
                print(f"   {difficulty.title()}: {count}")

if __name__ == '__main__':
    main()