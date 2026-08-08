from flask import Blueprint, jsonify, request

from app.services.scanner import scan_url


api = Blueprint("api", __name__, url_prefix="/api")


@api.route("/scan", methods=["POST"])
def scan():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    url = data.get("url")

    if not url:
        return jsonify({
            "success": False,
            "error": "URL is required."
        }), 400

    result = scan_url(url)

    if not result.get("success"):
        return jsonify(result), 400

    return jsonify(result), 200