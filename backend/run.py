from flask import Flask

from config import Config
from app.extensions import db, migrate
from app.routes import api

# Import model so Flask-Migrate detects it
from app.models.scan_history import ScanHistory


app = Flask(__name__)

app.config.from_object(Config)


# Initialize database
db.init_app(app)

# Initialize migrations
migrate.init_app(app, db)

# Register API routes
app.register_blueprint(api)


@app.route("/")
def home():
    return "Sentinel AI Backend is Running Successfully!"


if __name__ == "__main__":
    app.run(debug=True)