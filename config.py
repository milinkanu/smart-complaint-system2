import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'smart-complaint-secret-key-2024'
    
    # Check if we are running on Vercel
    is_vercel = os.environ.get('VERCEL') == '1'
    base_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Set default sqlite URI
    # On Vercel, the filesystem is read-only except for /tmp
    sqlite_uri = 'sqlite:////tmp/site.db' if is_vercel else f"sqlite:///{os.path.join(base_dir, 'site.db')}"
    
    # Handle DB URL from environment for PostgreSQL compatibility
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
    SQLALCHEMY_DATABASE_URI = db_url or sqlite_uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Read-only filesystem workaround for Vercel
    UPLOAD_FOLDER = '/tmp/uploads' if is_vercel else 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
