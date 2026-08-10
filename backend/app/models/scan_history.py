from app.extensions import db


class ScanHistory(db.Model):

    __tablename__ = "scan_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    url = db.Column(
        db.String(2048),
        nullable=False
    )

    risk_score = db.Column(
        db.Integer,
        nullable=False
    )

    verdict = db.Column(
        db.String(50),
        nullable=False
    )

    reasons = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False
    )

    def __repr__(self):
        return f"<ScanHistory {self.id} - {self.verdict}>"