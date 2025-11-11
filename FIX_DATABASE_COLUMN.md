# Исправление: добавление колонки celery_task_id

## Проблема
Колонка `celery_task_id` была добавлена в модель, но не существует в базе данных, что вызывает ошибку:
```
column scans.celery_task_id does not exist
```

## Решение

### Вариант 1: Автоматическое исправление (рекомендуется)
При следующем запуске контейнеров колонка будет добавлена автоматически через `startup.py`:

```bash
sudo docker-compose up --build -d
```

### Вариант 2: Ручное исправление
Если контейнеры уже запущены, выполните:

```bash
sudo docker-compose up -d postgres
sleep 5
sudo ./fix_celery_column.sh
sudo docker-compose restart api
```

### Вариант 3: Через psql напрямую
```bash
sudo docker-compose exec postgres psql -U cryptscan -d cryptscan_db -c "ALTER TABLE scans ADD COLUMN IF NOT EXISTS celery_task_id VARCHAR(255) NULL;"
```

## Проверка
После исправления проверьте, что колонка добавлена:
```bash
sudo docker-compose exec postgres psql -U cryptscan -d cryptscan_db -c "\d scans" | grep celery_task_id
```

