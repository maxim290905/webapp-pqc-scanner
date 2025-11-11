#!/bin/bash

echo "Adding celery_task_id column to scans table..."

# Connect to PostgreSQL and add column
sudo docker-compose exec -T postgres psql -U cryptscan -d cryptscan_db <<EOF
-- Check if column exists, if not add it
DO \$\$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name='scans' AND column_name='celery_task_id'
    ) THEN
        ALTER TABLE scans ADD COLUMN celery_task_id VARCHAR(255) NULL;
        RAISE NOTICE 'Column celery_task_id added successfully';
    ELSE
        RAISE NOTICE 'Column celery_task_id already exists';
    END IF;
END
\$\$;
EOF

echo "✓ Done!"

