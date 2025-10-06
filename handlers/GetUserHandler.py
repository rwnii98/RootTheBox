import json
import logging
from handlers.BaseHandlers import BaseHandler
from models import User

class GetUserHandler(BaseHandler):
    def check_xsrf_cookie(self):
        # Disable XSRF for this endpoint
        pass

    def post(self):
        try:
            data = json.loads(self.request.body)
            identifier = data.get("username")  # Could be username or email

            if not identifier:
                self.set_status(400)
                return self.write({"error": "Missing 'username' field"})

            # Try to find by username first
            user = User.by_handle(identifier)
            if not user:
                # If not found, try by email
                user = User.by_email(identifier)

            if not user:
                self.set_status(404)
                return self.write({"error": "User not found"})

            profile = {
                "user_id": str(user.id),
                "user_uuid": str(user.uuid),
                "username": user.handle,
                "email": user.email,
                "app_metadata": {
                    "theme_id": user.theme_id,
                    "team_id": user.team_id if user.team else None,
                    "is_admin": user.is_admin(),
                },
            }

            self.set_status(200)
            self.write(json.dumps(profile))

        except Exception as e:
            logging.exception("Error fetching user profile")
            self.set_status(500)
            self.write({"error": str(e)})
