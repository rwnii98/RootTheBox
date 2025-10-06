import logging
from datetime import datetime
from authlib.integrations.requests_client import OAuth2Session 
from handlers.BaseHandlers import BaseHandler
from tornado.options import options
from models.User import User
from models.Theme import Theme

from netaddr import IPAddress

class Auth0LoginHandler(BaseHandler):
    """Handles login via Auth0 (Auth0 validates credentials against local DB)"""

    AUTH0_DOMAIN = options.auth0_domain
    CLIENT_ID = options.auth0_client_id
    CLIENT_SECRET = options.auth0_client_secret
    REDIRECT_URI = options.auth0_redirect_url

    def get_oauth_client(self):
        """Return a synchronous OAuth2Session client"""
        return OAuth2Session(
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            scope="openid profile email",
            redirect_uri=self.REDIRECT_URI,
        )

    def get(self, *args, **kwargs):
        # Handle callback from Auth0
        if "code" in self.request.arguments:
            self.handle_auth0_callback()
            return

        # If already logged in, skip login
        user = self.get_current_user()
        if user:
            self.redirect("/user")
            return

        # Clear any stale sessions or cookies
        if self.session is not None:
            self.session.delete()
        self.clear_all_cookies()

        # Build Auth0 client
        client = self.get_oauth_client()

        # Create the authorization URL
        auth_url, state = client.create_authorization_url(
            f"https://{self.AUTH0_DOMAIN}/authorize"
        )

        # Save state in session for CSRF protection
        self.start_session()
        self.session["auth0_state"] = state
        self.session.save()

        # Redirect user to Auth0 login page
        logging.info(f"Redirecting to Auth0: {auth_url}")
        self.redirect(auth_url)

    def handle_auth0_callback(self):
        code = self.get_argument("code")
        state = self.get_argument("state")

        # Validate CSRF state
        if state != self.session.get("auth0_state"):
            logging.error("Invalid OAuth state")
            return self.failed_login()

        client = self.get_oauth_client()
        try:
            # Exchange the authorization code for a token
            token = client.fetch_token(
                f"https://{self.AUTH0_DOMAIN}/oauth/token",
                client_secret=self.CLIENT_SECRET,
                code=code,
                grant_type="authorization_code",
                redirect_uri=self.REDIRECT_URI
            )

            resp = client.get(
                f"https://{self.AUTH0_DOMAIN}/userinfo",
                headers={
                    "Authorization": f"Bearer {token}"
                }
            )

            # Parse JSON
            try:
                userinfo = resp.json()
                logging.info("Parsed JSON type: %s", type(userinfo))
                logging.info("Auth0 userinfo: %s", userinfo)
            except Exception as e:
                logging.exception("Failed to parse JSON from Auth0 /userinfo")

        except Exception:
            logging.exception("Auth0 login failed")
            return self.failed_login()

        # Map Auth0 email to local user
        email = userinfo.get("email")
        user = User.by_email(email)

        if user:
            logging.info("User found in RTB database: %s", {
                "id": user.id,
                "handle": user.handle,
                "email": user.email,
                "team_id": user.team.id if user.team else None,
                "is_admin": user.is_admin()
            })
            self.valid_login(user)  # sets session and redirects to /user
       
       
    def valid_login(self, user):
        """Process valid local user after Auth0 authentication"""

        if (
            options.require_email
            and options.validate_email
            and not user.is_admin()
            and not user.is_email_valid()
        ):
            logging.warning("Email not validated for user %s", user.handle)
            self.failed_login()
            return

        if user.locked:
            logging.warning("User %s is locked", user.handle)
            self.failed_login()
            return

        if user.is_expired():
            logging.warning("User %s is expired", user.handle)
            self.failed_login()
            return

        # Everything ok → successful login
        self.successful_login(user)
        self.redirect("/user")

    def successful_login(self, user):
        """Called when a user successfully logs in"""
        logging.info(
            "Successful login: %s from %s" % (user.handle, self.request.remote_ip)
        )
        user.last_login = datetime.now()
        user.logins += 1
        self.dbsession.add(user)
        self.dbsession.commit()
        self.start_session()
        theme = Theme.by_id(user.theme_id)
        if user.team is not None:
            self.session["team_id"] = int(user.team.id)
        self.session["user_id"] = int(user.id)
        self.session["user_uuid"] = user.uuid
        self.session["handle"] = user.handle
        self.session["theme"] = [str(f) for f in theme.files]
        self.session["theme_id"] = int(theme.id)
        self.session["menu"] = "admin" if user.is_admin() else "user"
        self.session.save()
