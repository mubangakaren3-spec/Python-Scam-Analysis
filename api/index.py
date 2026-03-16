import sys
import os

# Add the root directory to sys.path so we can import app_api
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from app_api import app
