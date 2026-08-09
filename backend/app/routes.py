from flask import Blueprint, jsonify, request

from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from app.extensions import db
from app.models.scan_history import ScanHistory
from app.models.user import User
from app.services.scanner import scan_url


api = Blueprint("api", __name__, url_prefix="/api")


# ============================================================
# REGISTER
# ============================================================

@api.route("/auth/register", methods=["POST"])
def register():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username:
        return jsonify({
            "success": False,
            "error": "Username is required."
        }), 400

    if not email:
        return jsonify({
            "success": False,
            "error": "Email is required."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "error": "Password is required."
        }), 400

    if len(password) < 8:
        return jsonify({
            "success": False,
            "error": "Password must be at least 8 characters."
        }), 400

    if User.query.filter_by(username=username).first():
        return jsonify({
            "success": False,
            "error": "Username already exists."
        }), 409

    if User.query.filter_by(email=email).first():
        return jsonify({
            "success": False,
            "error": "Email already exists."
        }), 409

    user = User(
        username=username,
        email=email
    )

    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "User registered successfully.",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "created_at": (
                user.created_at.isoformat()
                if user.created_at
                else None
            )
        }
    }), 201


# ============================================================
# LOGIN
# ============================================================

@api.route("/auth/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email:
        return jsonify({
            "success": False,
            "error": "Email is required."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "error": "Password is required."
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({
            "success": False,
            "error": "Invalid email or password."
        }), 401

    access_token = create_access_token(
        identity=str(user.id)
    )

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }), 200


# ============================================================
# SCAN URL
# ============================================================

@api.route("/scan", methods=["POST"])
@jwt_required()
def scan():

    user_id = int(get_jwt_identity())

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

    scan_record = ScanHistory(
        user_id=user_id,
        url=result["url"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        reasons=", ".join(result["reasons"])
    )

    db.session.add(scan_record)
    db.session.commit()

    result["scan_id"] = scan_record.id

    return jsonify(result), 200


# ============================================================
# GET USER'S HISTORY
# ============================================================

@api.route("/history", methods=["GET"])
@jwt_required()
def history():

    user_id = int(get_jwt_identity())

    scans = ScanHistory.query.filter_by(
        user_id=user_id
    ).order_by(
        ScanHistory.created_at.desc()
    ).all()

    history_data = []

    for scan in scans:

        history_data.append({
            "scan_id": scan.id,
            "url": scan.url,
            "risk_score": scan.risk_score,
            "verdict": scan.verdict,
            "reasons": (
                scan.reasons.split(", ")
                if scan.reasons
                else []
            ),
            "created_at": (
                scan.created_at.isoformat()
                if scan.created_at
                else None
            )
        })

    return jsonify({
        "success": True,
        "count": len(history_data),
        "history": history_data
    }), 200


# ============================================================
# GET SINGLE SCAN
# ============================================================

@api.route("/history/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):

    user_id = int(get_jwt_identity())

    scan = ScanHistory.query.filter_by(
        id=scan_id,
        user_id=user_id
    ).first()

    if not scan:
        return jsonify({
            "success": False,
            "error": "Scan history not found."
        }), 404

    scan_data = {
        "scan_id": scan.id,
        "url": scan.url,
        "risk_score": scan.risk_score,
        "verdict": scan.verdict,
        "reasons": (
            scan.reasons.split(", ")
            if scan.reasons
            else []
        ),
        "created_at": (
            scan.created_at.isoformat()
            if scan.created_at
            else None
        )
    }

    return jsonify({
        "success": True,
        "scan": scan_data
    }), 200


# ============================================================
# DELETE SINGLE SCAN
# ============================================================

@api.route("/history/<int:scan_id>", methods=["DELETE"])
@jwt_required()
def delete_scan(scan_id):

    user_id = int(get_jwt_identity())

    scan = ScanHistory.query.filter_by(
        id=scan_id,
        user_id=user_id
    ).first()

    if not scan:
        return jsonify({
            "success": False,
            "error": "Scan history not found."
        }), 404

    db.session.delete(scan)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Scan history deleted successfully."
    }), 200


# ============================================================
# CLEAR USER'S HISTORY
# ============================================================

@api.route("/history", methods=["DELETE"])
@jwt_required()
def clear_history():

    user_id = int(get_jwt_identity())

    deleted_count = ScanHistory.query.filter_by(
        user_id=user_id
    ).delete(
        synchronize_session=False
    )

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "All scan history deleted successfully.",
        "deleted_count": deleted_count
    }), 200