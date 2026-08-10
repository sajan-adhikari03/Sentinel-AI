import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, current_app

from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from app.extensions import db
from app.models.scan_history import ScanHistory
from app.models.user import User
from app.services.scanner import scan_url


api = Blueprint(
    "api",
    __name__,
    url_prefix="/api"
)


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

    # ========================================================
    # STRONG PASSWORD VALIDATION
    # ========================================================

    if len(password) < 8:
        return jsonify({
            "success": False,
            "error": "Password must be at least 8 characters."
        }), 400

    if " " in password:
        return jsonify({
            "success": False,
            "error": "Password must not contain spaces."
        }), 400

    if not re.search(r"[A-Z]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one uppercase letter."
        }), 400

    if not re.search(r"[a-z]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one lowercase letter."
        }), 400

    if not re.search(r"[0-9]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one number."
        }), 400

    if not re.search(r"[^A-Za-z0-9\s]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one special character."
        }), 400

    # ========================================================
    # DUPLICATE CHECK
    # ========================================================

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

    # ========================================================
    # CREATE USER
    # ========================================================

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

    user = User.query.filter_by(
        email=email
    ).first()

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
# FORGOT PASSWORD
# ============================================================

@api.route("/auth/forgot-password", methods=["POST"])
def forgot_password():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    email = data.get(
        "email",
        ""
    ).strip().lower()

    if not email:
        return jsonify({
            "success": False,
            "error": "Email is required."
        }), 400

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:
        return jsonify({
            "success": True,
            "message": (
                "If an account exists for this email, "
                "a password reset request has been created."
            )
        }), 200

    reset_token = secrets.token_urlsafe(32)

    reset_token_hash = hashlib.sha256(
        reset_token.encode("utf-8")
    ).hexdigest()

    reset_token_expires_at = (
        datetime.utcnow()
        + timedelta(minutes=15)
    )

    user.reset_token_hash = reset_token_hash
    user.reset_token_expires_at = (
        reset_token_expires_at
    )

    db.session.commit()

    response = {
        "success": True,
        "message": "Password reset request created."
    }

    if current_app.debug:
        response["development_only"] = True
        response["reset_token"] = reset_token
        response["expires_in_minutes"] = 15

    return jsonify(response), 200


# ============================================================
# RESET PASSWORD
# ============================================================

@api.route("/auth/reset-password", methods=["POST"])
def reset_password():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    reset_token = data.get(
        "reset_token",
        ""
    )

    password = data.get(
        "password",
        ""
    )

    confirm_password = data.get(
        "confirm_password",
        ""
    )

    if not reset_token:
        return jsonify({
            "success": False,
            "error": "Reset token is required."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "error": "Password is required."
        }), 400

    if not confirm_password:
        return jsonify({
            "success": False,
            "error": "Confirm password is required."
        }), 400

    if password != confirm_password:
        return jsonify({
            "success": False,
            "error": "Passwords do not match."
        }), 400

    if len(password) < 8:
        return jsonify({
            "success": False,
            "error": "Password must be at least 8 characters."
        }), 400

    if " " in password:
        return jsonify({
            "success": False,
            "error": "Password must not contain spaces."
        }), 400

    if not re.search(r"[A-Z]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one uppercase letter."
        }), 400

    if not re.search(r"[a-z]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one lowercase letter."
        }), 400

    if not re.search(r"[0-9]", password):
        return jsonify({
            "success": False,
            "error": "Password must contain at least one number."
        }), 400

    if not re.search(
        r"[^A-Za-z0-9\s]",
        password
    ):
        return jsonify({
            "success": False,
            "error": (
                "Password must contain at least one special character."
            )
        }), 400

    reset_token_hash = hashlib.sha256(
        reset_token.encode("utf-8")
    ).hexdigest()

    user = User.query.filter_by(
        reset_token_hash=reset_token_hash
    ).first()

    if not user:
        return jsonify({
            "success": False,
            "error": "Invalid or expired reset token."
        }), 400

    if (
        not user.reset_token_expires_at
        or user.reset_token_expires_at
        < datetime.utcnow()
    ):

        user.reset_token_hash = None
        user.reset_token_expires_at = None

        db.session.commit()

        return jsonify({
            "success": False,
            "error": "Invalid or expired reset token."
        }), 400

    user.set_password(password)

    user.reset_token_hash = None
    user.reset_token_expires_at = None

    db.session.commit()

    return jsonify({
        "success": True,
        "message": (
            "Password reset successfully. "
            "Please login with your new password."
        )
    }), 200


# ============================================================
# SCAN URL
# ============================================================

@api.route("/scan", methods=["POST"])
@jwt_required()
def scan():

    user_id = int(
        get_jwt_identity()
    )

    data = request.get_json(
        silent=True
    )

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

    # ========================================================
    # RUN COMPLETE SENTINEL SCANNER
    # ========================================================

    result = scan_url(url)

    if not result.get("success"):
        return jsonify(result), 400

    # ========================================================
    # STORE COMPLETE SCAN RESULT
    #
    # We use the existing `reasons` TEXT column to store
    # structured JSON so no database migration is required.
    # ========================================================

    history_payload = {
        "reasons": result.get(
            "reasons",
            []
        ),

        "ml_prediction": result.get(
            "ml_prediction"
        ),

        "ml_probability": result.get(
            "ml_probability"
        ),

        "ml_verdict": result.get(
            "ml_verdict"
        ),

        "trusted_domain": result.get(
            "trusted_domain",
            False
        ),

        "brand_impersonation": result.get(
            "brand_impersonation"
        ),

        "detection_source": result.get(
            "detection_source"
        ),

        "rule_score": result.get(
            "rule_score",
            0
        ),

        "rule_verdict": result.get(
            "rule_verdict",
            "SAFE"
        ),

        "features": result.get(
            "features",
            {}
        )
    }

    scan_record = ScanHistory(
        user_id=user_id,
        url=result["url"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],

        # Store complete scan information as JSON.
        reasons=json.dumps(
            history_payload,
            ensure_ascii=False
        )
    )

    db.session.add(
        scan_record
    )

    db.session.commit()

    # Add database ID to API result.
    result["scan_id"] = scan_record.id

    return jsonify(
        result
    ), 200


# ============================================================
# HELPER
# ============================================================

def parse_history_details(scan):

    """
    Converts the stored reasons field back into the complete
    Sentinel scan result.

    Supports BOTH:
    1. New JSON-based history records.
    2. Old records created before this fix.
    """

    default_data = {
        "reasons": [],
        "ml_prediction": None,
        "ml_probability": None,
        "ml_verdict": None,
        "trusted_domain": False,
        "brand_impersonation": None,
        "detection_source": "RULE_ENGINE",
        "rule_score": None,
        "rule_verdict": None,
        "features": {}
    }

    if not scan.reasons:
        return default_data

    # --------------------------------------------------------
    # Try new JSON format
    # --------------------------------------------------------

    try:

        parsed = json.loads(
            scan.reasons
        )

        if isinstance(parsed, dict):

            default_data.update(
                parsed
            )

            return default_data

    except (
        json.JSONDecodeError,
        TypeError
    ):
        pass

    # --------------------------------------------------------
    # OLD FORMAT
    # --------------------------------------------------------

    if isinstance(
        scan.reasons,
        str
    ):

        default_data["reasons"] = (
            scan.reasons.split(", ")
            if scan.reasons
            else []
        )

    return default_data


# ============================================================
# GET USER'S HISTORY
# ============================================================

@api.route("/history", methods=["GET"])
@jwt_required()
def history():

    user_id = int(
        get_jwt_identity()
    )

    scans = (
        ScanHistory.query
        .filter_by(
            user_id=user_id
        )
        .order_by(
            ScanHistory.created_at.desc()
        )
        .all()
    )

    history_data = []

    for scan in scans:

        details = parse_history_details(
            scan
        )

        history_data.append({

            # Both names are returned for compatibility.
            "id": scan.id,
            "scan_id": scan.id,

            "url": scan.url,

            "risk_score": scan.risk_score,

            "verdict": scan.verdict,

            # Detection reasons.
            "reasons": details.get(
                "reasons",
                []
            ),

            # ML information.
            "ml_prediction": details.get(
                "ml_prediction"
            ),

            "ml_probability": details.get(
                "ml_probability"
            ),

            "ml_verdict": details.get(
                "ml_verdict"
            ),

            # Security intelligence.
            "trusted_domain": details.get(
                "trusted_domain",
                False
            ),

            "brand_impersonation": details.get(
                "brand_impersonation"
            ),

            "detection_source": details.get(
                "detection_source"
            ),

            # Rule engine.
            "rule_score": details.get(
                "rule_score"
            ),

            "rule_verdict": details.get(
                "rule_verdict"
            ),

            # URL features.
            "features": details.get(
                "features",
                {}
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

@api.route(
    "/history/<int:scan_id>",
    methods=["GET"]
)
@jwt_required()
def get_scan(scan_id):

    user_id = int(
        get_jwt_identity()
    )

    scan = (
        ScanHistory.query
        .filter_by(
            id=scan_id,
            user_id=user_id
        )
        .first()
    )

    if not scan:
        return jsonify({
            "success": False,
            "error": "Scan history not found."
        }), 404

    details = parse_history_details(
        scan
    )

    scan_data = {

        "id": scan.id,
        "scan_id": scan.id,

        "url": scan.url,

        "risk_score": scan.risk_score,

        "verdict": scan.verdict,

        "reasons": details.get(
            "reasons",
            []
        ),

        "ml_prediction": details.get(
            "ml_prediction"
        ),

        "ml_probability": details.get(
            "ml_probability"
        ),

        "ml_verdict": details.get(
            "ml_verdict"
        ),

        "trusted_domain": details.get(
            "trusted_domain",
            False
        ),

        "brand_impersonation": details.get(
            "brand_impersonation"
        ),

        "detection_source": details.get(
            "detection_source"
        ),

        "rule_score": details.get(
            "rule_score"
        ),

        "rule_verdict": details.get(
            "rule_verdict"
        ),

        "features": details.get(
            "features",
            {}
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

@api.route(
    "/history/<int:scan_id>",
    methods=["DELETE"]
)
@jwt_required()
def delete_scan(scan_id):

    user_id = int(
        get_jwt_identity()
    )

    scan = (
        ScanHistory.query
        .filter_by(
            id=scan_id,
            user_id=user_id
        )
        .first()
    )

    if not scan:
        return jsonify({
            "success": False,
            "error": "Scan history not found."
        }), 404

    db.session.delete(
        scan
    )

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Scan history deleted successfully."
    }), 200


# ============================================================
# CLEAR USER'S HISTORY
# ============================================================

@api.route(
    "/history",
    methods=["DELETE"]
)
@jwt_required()
def clear_history():

    user_id = int(
        get_jwt_identity()
    )

    deleted_count = (
        ScanHistory.query
        .filter_by(
            user_id=user_id
        )
        .delete(
            synchronize_session=False
        )
    )

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "All scan history deleted successfully.",
        "deleted_count": deleted_count
    }), 200