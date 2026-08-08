from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models.scan_history import ScanHistory
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

    scan_record = ScanHistory(
        url=result["url"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        reasons=", ".join(result["reasons"])
    )

    db.session.add(scan_record)
    db.session.commit()

    result["scan_id"] = scan_record.id

    return jsonify(result), 200


@api.route("/history", methods=["GET"])
def history():

    scans = ScanHistory.query.order_by(
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


@api.route("/history/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):

    scan = ScanHistory.query.get(scan_id)

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


@api.route("/history/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):

    scan = ScanHistory.query.get(scan_id)

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


@api.route("/history", methods=["DELETE"])
def clear_history():

    deleted_count = ScanHistory.query.delete(
        synchronize_session=False
    )

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "All scan history deleted successfully.",
        "deleted_count": deleted_count
    }), 200