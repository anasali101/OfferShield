"""OfferShield application factory."""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from config import Config
from routes.analysis import analysis_bp
from routes.main import main_bp
from services import storage


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    storage.init_db(app.config["DB_PATH"])
    storage.cleanup_expired(app.config["DB_PATH"], app.config["DOC_INDEX_TTL_DAYS"])

    app.register_blueprint(main_bp)
    app.register_blueprint(analysis_bp)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; font-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if request.path.startswith("/results/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.errorhandler(413)
    def too_large(_error):
        message = f"File is too large. Maximum upload size is {app.config['MAX_UPLOAD_MB']} MB."
        if request.path.startswith("/api/"):
            return jsonify({"error": message}), 413
        return render_template("error.html", code=413, message=message), 413

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return render_template("error.html", code=404, message="That page does not exist."), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Method not allowed"}), 405
        return render_template("error.html", code=405, message="Method not allowed."), 405

    @app.errorhandler(500)
    def server_error(error):
        logging.exception("Unhandled error: %s", error)
        if request.path.startswith("/api/"):
            return jsonify({"error": "An internal error occurred. No data was retained."}), 500
        return (
            render_template(
                "error.html",
                code=500,
                message="An internal error occurred. Please try again.",
            ),
            500,
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
