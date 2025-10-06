# handlers/Auth0ChangePasswordHandler.py
import json
import logging
from handlers.BaseHandlers import BaseHandler
from tornado.options import options
from pbkdf2 import PBKDF2
from models.User import User

# Shared secret for Auth0 validation
AUTH0_SHARED_SECRET = options.auth0_shared_secret

class Auth0ChangePasswordHandler(BaseHandler):
    """
    POST /auth/change_password
    Body: {"account": "...", "new_password": "..."}
    Header: X-Auth-Secret: <shared-secret>
    Response: 200 {"success": true} or 401 {"success": false}
    """
    def check_xsrf_cookie(self):
        # Disable XSRF just for this endpoint
        pass

    def post(self):
        # Verify shared secret
        secret = self.request.headers.get("X-Auth-Secret")
        if not secret or secret != AUTH0_SHARED_SECRET:
            logging.warning("Unauthorized password change request from %s", self.request.remote_ip)
            self.set_status(403)
            return self.write({"success": False, "error": "forbidden"})

        # Parse JSON body
        try:
            body = json.loads(self.request.body.decode("utf-8") or "{}")
        except Exception:
            self.set_status(400)
            return self.write({"success": False, "error": "invalid_json"})

        account = body.get("account")
        new_password = body.get("new_password")

        if not account or not new_password:
            self.set_status(400)
            return self.write({"success": False, "error": "missing_fields"})

        # Lookup user by handle or email
        user = User.by_handle(account)
        if user is None:
            user = User.by_email(account)

        if user is None:
            self.set_status(404)
            return self.write({"success": False, "error": "user_not_found"})

        # Set new password
        user.password = new_password
        self.dbsession.add(user)
        self.dbsession.commit()
        logging.info("Password successfully changed for user %s", account)

        self.write({"success": True})
