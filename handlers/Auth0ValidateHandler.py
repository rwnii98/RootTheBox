# handlers/Auth0ValidateHandler.py
import json
import logging
from handlers.BaseHandlers import BaseHandler
from tornado.options import options
from netaddr import IPAddress
from pbkdf2 import PBKDF2
from models.User import User  # adapt import if your path is different

# Shared secret for Auth0 validation
AUTH0_SHARED_SECRET = options.auth0_shared_secret 

class Auth0ValidateHandler(BaseHandler):
    """
    POST /auth/validate
    Body: {"account": "...", "password": "..."}
    Header: X-Auth-Secret: <shared-secret>
    Response: 200 {"success": true, "user": {...}} or 401 {"success": false}
    """
    def check_xsrf_cookie(self):
        # Disable XSRF just for this endpoint
        pass

    def post(self):
        # Check shared secret header
        secret = self.request.headers.get("X-Auth-Secret")
        if not secret or secret != AUTH0_SHARED_SECRET:
            logging.warning("Unauthorized auth validate request from %s", self.request.remote_ip)
            self.set_status(403)
            return self.write({"success": False, "error": "forbidden"})

        # Parse JSON body
        try:
            body = json.loads(self.request.body.decode("utf-8") or "{}")
        except Exception:
            self.set_status(400)
            return self.write({"success": False, "error": "invalid_json"})

        account = body.get("account")
        password = body.get("password")

        if not account or not password:
            self.set_status(400)
            return self.write({"success": False, "error": "missing_fields"})

        # Lookup user by handle or email
        user = User.by_handle(account)
        if user is None:
            user = User.by_email(account)

        if user is None or not user.validate_password(password):
            # simulate hashing to mitigate timing attacks
            PBKDF2.crypt(password, "BurnTheHashTime")
            # Get IP and shared state from RTB app settings
            ip = self.request.remote_ip
            failed_logins = self.application.settings["failed_logins"]

            # Increment failed login attempts
            failed_logins[ip] = failed_logins.get(ip, 0) + 1
            logging.warning("*** Failed login attempt from %s (attempt %d)", ip, failed_logins[ip])

            # apply automatic ban threshold
            threshold = self.application.settings["blacklist_threshold"]
            if (
                self.application.settings.get("automatic_ban")
                and failed_logins[ip] >= threshold
            ):
                logging.info("[BAN HAMMER] Automatically banned IP: %s" % ip)
                try:
                    if not IPAddress(ip).is_loopback():
                        self.application.settings["blacklisted_ips"].append(ip)
                    else:
                        logging.warning("[BAN HAMMER] Cannot blacklist loopback address")
                except Exception:
                    logging.exception("Error while attempting to ban IP")

            self.set_status(401)
            return self.write({"success": False, "error": "invalid_credentials"})

        # Return minimal profile Auth0 expects
        profile = {
            "user_id": str(user.id),
            "user_uuid": user.uuid,
            "email": user.email,
            "handle": user.handle,
            "app_metadata": {
                "theme_id": user.theme_id,
                "team_id": user.team.id if user.team else None,
                "is_admin": user.is_admin(),
            },
        }

        # Reset failed login count on success
        ip = self.request.remote_ip
        failed_logins = self.application.settings["failed_logins"]
        if ip in failed_logins:
            failed_logins[ip] = 0
            logging.info("Reset failed login count for IP %s", ip)

        self.write({"success": True, "user": profile})
