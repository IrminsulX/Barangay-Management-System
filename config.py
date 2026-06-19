import os
from flask import Flask

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'brgy-mgmt-sys-secret-key-change-in-production')
DATABASE = os.path.join(os.path.dirname(__file__), 'barangay.db')
ADMIN_ROLES = ('admin', 'staff', 'barangay_captain', 'kagawad', 'secretary_treasurer', 'sk_chairperson', 'tanod')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
DAY_NAMES = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
