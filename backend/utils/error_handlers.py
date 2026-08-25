"""
ADFIR Platform — Centralised Error Handlers
=============================================
Registers JSON error responses for all standard HTTP error codes.
All error responses follow the same envelope:
  { "error": { "code": int, "message": str, "details": any|null } }
"""

import logging
from flask import Flask, jsonify
from flask_jwt_extended.exceptions import NoAuthorizationError
from jwt.exceptions import InvalidTokenError

logger = logging.getLogger(__name__)


def _error_response(code: int, message: str, details=None):
    """Build a standard error envelope."""
    return jsonify({"error": {"code": code, "message": message, "details": details}}), code


def register_error_handlers(app: Flask) -> None:
    """Attach all error handlers to the Flask application."""

    @app.errorhandler(400)
    def bad_request(e):
        return _error_response(400, "Bad request", str(e))

    @app.errorhandler(401)
    def unauthorized(e):
        return _error_response(401, "Authentication required")

    @app.errorhandler(403)
    def forbidden(e):
        return _error_response(403, "You do not have permission to perform this action")

    @app.errorhandler(404)
    def not_found(e):
        return _error_response(404, "The requested resource was not found")

    @app.errorhandler(405)
    def method_not_allowed(e):
        return _error_response(405, "HTTP method not allowed on this endpoint")

    @app.errorhandler(422)
    def unprocessable(e):
        return _error_response(422, "Request validation failed", str(e))

    @app.errorhandler(429)
    def rate_limited(e):
        return _error_response(429, "Too many requests — please slow down")

    @app.errorhandler(500)
    def internal_error(e):
        logger.exception("Unhandled server error: %s", e)
        return _error_response(500, "An unexpected server error occurred")

    @app.errorhandler(NoAuthorizationError)
    def missing_token(e):
        return _error_response(401, "Missing or invalid authorization token")

    logger.debug("Error handlers registered.")


class ResourceNotFoundError(Exception):
    """Raised when a requested DB record does not exist."""
    pass


class PermissionDeniedError(Exception):
    """Raised when the authenticated user lacks the required role."""
    pass


class ValidationError(Exception):
    """Raised when input validation fails outside of Marshmallow."""
    pass


class EvidenceTamperedException(Exception):
    """
    Raised by the Evidence Vault when a retrieved artifact's SHA-256 hash
    does not match the stored hash — indicating potential tampering.
    """
    pass
