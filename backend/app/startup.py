"""
Startup script to initialize database and create default admin user
"""
from app.database import SessionLocal, engine, Base
from app.models import User, UserRole
from app.auth import get_password_hash
from app.config import settings
from sqlalchemy import text, inspect


def init_db():
    """Initialize database tables and create default admin user"""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Add missing columns if they don't exist (for migrations)
    db = SessionLocal()
    try:
        inspector = inspect(engine)
        columns = [col['name'] for col in inspector.get_columns('scans')]
        
        # Add celery_task_id column if it doesn't exist
        if 'celery_task_id' not in columns:
            db.execute(text("ALTER TABLE scans ADD COLUMN celery_task_id VARCHAR(255) NULL"))
            db.commit()
            print("✓ Added celery_task_id column to scans table")
        
        # Check if admin exists
        admin = db.query(User).filter(User.email == "admin@example.com").first()
        if not admin:
            # Create admin user
            admin = User(
                email="admin@example.com",
                name="Admin User",
                password_hash=get_password_hash("admin123"),
                role=UserRole.ADMIN
            )
            db.add(admin)
            db.commit()
            print("✓ Admin user created: admin@example.com / admin123")
        else:
            print("✓ Admin user already exists")
    except Exception as e:
        print(f"✗ Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()

