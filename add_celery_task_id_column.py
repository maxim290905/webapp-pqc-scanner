#!/usr/bin/env python3
"""
Script to add celery_task_id column to scans table
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.database import SessionLocal, engine
from sqlalchemy import text

def add_celery_task_id_column():
    """Add celery_task_id column to scans table if it doesn't exist"""
    db = SessionLocal()
    try:
        # Check if column exists
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='scans' AND column_name='celery_task_id'
        """))
        
        if result.fetchone():
            print("✓ Column celery_task_id already exists")
            return
        
        # Add column
        db.execute(text("""
            ALTER TABLE scans 
            ADD COLUMN celery_task_id VARCHAR(255) NULL
        """))
        db.commit()
        print("✓ Column celery_task_id added successfully")
    except Exception as e:
        print(f"✗ Error adding column: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    print("Adding celery_task_id column to scans table...")
    add_celery_task_id_column()

