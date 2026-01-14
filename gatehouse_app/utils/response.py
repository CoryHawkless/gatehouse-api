"""API response utilities."""
from flask import jsonify, g


# Version for the response envelope
ENVELOPE_VERSION = "1.0"


def api_response(
    *,
    data=None,
    success=True,
    message="",
    status=200,
    error_type=None,
    error_details=None,
    meta=None
):
    """
    Create a standardized API response.

    Args:
        data: Response data (only included if success=True)
        success: Whether the request was successful
        message: Human-readable message
        status: HTTP status code
        error_type: Type of error (only if success=False)
        error_details: Additional error details (only if success=False)
        meta: Additional metadata (pagination, etc.)

    Returns:
        Tuple of (response, status_code)
    """
    payload = {
        "version": ENVELOPE_VERSION,
        "success": success,
        "code": status,
        "message": message,
        "request_id": g.get("request_id", "unknown"),
    }

    if meta:
        payload["meta"] = meta

    if success:
        if data is not None:
            payload["data"] = data
    else:
        payload["error"] = {
            "type": error_type or "UNKNOWN",
            "details": error_details or {}
        }

    return jsonify(payload), status
