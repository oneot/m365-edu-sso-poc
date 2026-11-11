"""gunicorn 진입점: gunicorn wsgi:app"""
from app import create_app

app = create_app()
