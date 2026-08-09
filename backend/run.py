from flask import Flask

from config import Config
from app.extensions import db, migrate
from app.routes import api

# JWT
from flask_jwt_extended import JWTManager

# Import models so Flask-Migrate detects them
from app.models.scan_history import ScanHistory
from app.models.user import User


app = Flask(__name__)

app.config.from_object(Config)

# JWT configuration
app.config["JWT_SECRET_KEY"] = "sentinel-super-secret-key-change-this-later"

# Initialize database
db.init_app(app)

# Initialize migrations
migrate.init_app(app, db)

# Initialize JWT
jwt = JWTManager(app)

# Register API routes
app.register_blueprint(api)


@app.route("/")
def home():
    return "Sentinel AI Backend is Running Successfully!"


if __name__ == "__main__":
    app.run(debug=True)