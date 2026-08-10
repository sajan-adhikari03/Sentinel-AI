from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from config import Config
from app.extensions import db, migrate
from app.routes import api

# Import models so Flask-Migrate detects them
from app.models.scan_history import ScanHistory
from app.models.user import User


app = Flask(__name__)

app.config.from_object(Config)


# ============================================================
# CORS
# ============================================================

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173"
            ]
        }
    }
)


# ============================================================
# JWT
# ============================================================

jwt = JWTManager(app)


# ============================================================
# DATABASE
# ============================================================

db.init_app(app)


# ============================================================
# MIGRATIONS
# ============================================================

migrate.init_app(app, db)


# ============================================================
# API ROUTES
# ============================================================

app.register_blueprint(api)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return "Sentinel AI Backend is Running Successfully!"


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)