from flask import Flask
from config import Config
from app.routes import api

app = Flask(__name__)
app.config.from_object(Config)
app.register_blueprint(api)

@app.route("/")
def home():
    return "Sentinel AI Backend is Running Successfully!"


if __name__ == "__main__":
    app.run(debug=True)
