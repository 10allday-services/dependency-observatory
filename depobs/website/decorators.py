from functools import wraps

from flask import g, request
from werkzeug.security import safe_str_cmp


def basic_auth_required(required_username: str, required_password: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.authorization:
                return False, dict(error="Missing Authorization header"), 401

            request_username = request.authorization.get("username", None)
            request_password = request.authorization.get("password", None)

            if safe_str_cmp(request_username, required_username) and safe_str_cmp(
                request_password, required_password
            ):
                return (
                    False,
                    dict(error="Invalid username or password in Authorization header"),
                    401,
                )

            return f(*args, **kwargs)

        return decorated_function

    return decorator
