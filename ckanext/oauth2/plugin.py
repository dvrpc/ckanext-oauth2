# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import base64
from functools import partial
import json
import logging
import os
from urllib.parse import urlparse, urljoin

from flask import Blueprint
import jwt
from oauthlib.oauth2 import InsecureTransportError
import requests
from requests_oauthlib import OAuth2Session

from ckan import plugins
from ckan.common import g, session
from ckan.lib import helpers
import ckan.model as model
from ckan.plugins import toolkit

from ckanext.oauth2 import db


REQUIRED_CONF = (
    "authorization_endpoint",
    "token_endpoint",
    "client_id",
    "client_secret",
    "profile_api_url",
    "profile_api_user_field",
    "profile_api_mail_field",
)

CAME_FROM_FIELD = "came_from"
INITIAL_PAGE = "/dashboard"
REDIRECT_URL = "oauth2/callback"

log = logging.getLogger(__name__)


def generate_state(url):
    return base64.b64encode(json.dumps({CAME_FROM_FIELD: url}).encode())


def get_came_from(state):
    return json.loads(base64.b64decode(state)).get(CAME_FROM_FIELD, "/")


def no_permissions(context, msg):
    user = context["user"]
    return {"success": False, "msg": msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._("Users cannot be created.")
    return no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._("Users cannot be edited.")
    return no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._("Users cannot reset passwords.")
    return no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._("Users cannot reset passwords.")
    return no_permissions(context, msg)


def get_previous_page(default_page=INITIAL_PAGE):
    """Get page user attempts to log in from, or dashboard if unable to/in certain circumstances."""
    if "came_from" not in toolkit.request.params:
        came_from_url = toolkit.request.headers.get("Referer", default_page)
    else:
        came_from_url = toolkit.request.params.get("came_from", default_page)

    came_from_url_parsed = urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if came_from_url_parsed.netloc != "" and came_from_url_parsed.netloc != toolkit.request.host:
        came_from_url = default_page

    # When user is being logged in and REFERER == HOME or LOGOUT_PAGE, redirect to dashboard
    pages = ["/", "/user/logged_out_redirect"]
    if came_from_url_parsed.path in pages:
        came_from_url = default_page

    return came_from_url


class OAuth2Plugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None):
        """Store the OAuth 2 client configuration"""
        log.debug("Init OAuth2 extension")

        self.verify_https = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT", "") == ""

        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = os.environ.get(
            "CKAN_OAUTH2_JWT_ENABLE", toolkit.config.get("ckan.oauth2.jwt.enable", "")
        ).strip().lower() in ("true", "1", "on")

        self.authorization_endpoint = os.environ.get(
            "CKAN_OAUTH2_AUTHORIZATION_ENDPOINT",
            toolkit.config.get("ckan.oauth2.authorization_endpoint", ""),
        ).strip()

        self.token_endpoint = os.environ.get(
            "CKAN_OAUTH2_TOKEN_ENDPOINT",
            toolkit.config.get("ckan.oauth2.token_endpoint", ""),
        ).strip()

        self.profile_api_url = os.environ.get(
            "CKAN_OAUTH2_PROFILE_API_URL", toolkit.config.get("ckan.oauth2.profile_api_url", "")
        ).strip()

        self.client_id = os.environ.get(
            "CKAN_OAUTH2_CLIENT_ID", toolkit.config.get("ckan.oauth2.client_id", "")
        ).strip()

        self.client_secret = os.environ.get(
            "CKAN_OAUTH2_CLIENT_SECRET", toolkit.config.get("ckan.oauth2.client_secret", "")
        ).strip()

        self.scope = os.environ.get(
            "CKAN_OAUTH2_SCOPE", toolkit.config.get("ckan.oauth2.scope", "")
        ).strip()

        self.rememberer_name = os.environ.get(
            "CKAN_OAUTH2_REMEMBER_NAME",
            toolkit.config.get("ckan.oauth2.rememberer_name", "auth_tkt"),
        ).strip()

        self.profile_api_user_field = os.environ.get(
            "CKAN_OAUTH2_PROFILE_API_USER_FIELD",
            toolkit.config.get("ckan.oauth2.profile_api_user_field", ""),
        ).strip()

        self.profile_api_fullname_field = os.environ.get(
            "CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD",
            toolkit.config.get("ckan.oauth2.profile_api_fullname_field", ""),
        ).strip()

        self.profile_api_mail_field = os.environ.get(
            "CKAN_OAUTH2_PROFILE_API_MAIL_FIELD",
            toolkit.config.get("ckan.oauth2.profile_api_mail_field", ""),
        ).strip()

        self.profile_api_groupmembership_field = os.environ.get(
            "CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD",
            toolkit.config.get("ckan.oauth2.profile_api_groupmembership_field", ""),
        ).strip()

        self.sysadmin_group_name = os.environ.get(
            "CKAN_OAUTH2_SYSADMIN_GROUP_NAME",
            toolkit.config.get("ckan.oauth2.sysadmin_group_name", ""),
        ).strip()

        self.redirect_uri = urljoin(
            urljoin(
                toolkit.config.get("ckan.site_url", "http://localhost:5000"),
                toolkit.config.get("ckan.root_path"),
            ),
            REDIRECT_URL,
        )

        # Init db
        db.init_db(model)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None
        """
        # these still need to be added as rules to the blueprint
        # Redirect the user to the OAuth service register page
        if self.register_url:
            redirect("/user/register", self.register_url)

        # Redirect the user to the OAuth service reset page
        if self.reset_url:
            redirect("/user/reset", self.reset_url)

        # Redirect the user to the OAuth service reset page
        if self.edit_url:
            redirect("/user/edit/{user}", self.edit_url)
        """

    def get_blueprint(self):
        """Create Flask blueprint."""
        blueprint = Blueprint("oauth2", self.__module__)
        rules = [
            ("/user/login", "login", self.login),
            ("/oauth2/callback", "callback", self.callback),
        ]

        for rule in rules:
            blueprint.add_url_rule(*rule)

        return blueprint

    def get_auth_functions(self):
        """Prevent some actions from being authorized."""
        return {
            "user_create": user_create,
            "user_update": user_update,
            "user_reset": user_reset,
            "request_reset": request_reset,
        }

    def update_config(self, config):
        """Update configuration."""
        self.register_url = os.environ.get(
            "CKAN_OAUTH2_REGISTER_URL", config.get("ckan.oauth2.register_url", None)
        )
        self.reset_url = os.environ.get(
            "CKAN_OAUTH2_RESET_URL", config.get("ckan.oauth2.reset_url", None)
        )
        self.edit_url = os.environ.get(
            "CKAN_OAUTH2_EDIT_URL", config.get("ckan.oauth2.edit_url", None)
        )
        self.authorization_header = os.environ.get(
            "CKAN_OAUTH2_AUTHORIZATION_HEADER",
            config.get("ckan.oauth2.authorization_header", "Authorization"),
        ).lower()

        # Add plugin's templates dir to CKAN's extra_template_paths, so CKAN will use them
        plugins.toolkit.add_template_directory(config, "templates")

    def login(self):
        """Start log in process."""
        log.debug("login")

        state = generate_state(get_previous_page())
        oauth = OAuth2Session(
            self.client_id, redirect_uri=self.redirect_uri, scope=self.scope, state=state
        )
        auth_url, _ = oauth.authorization_url(self.authorization_endpoint)
        log.debug(f"Challenge: Redirecting challenge to page {auth_url}")

        return toolkit.redirect_to(auth_url)

    def callback(self):
        """Resume login process from authorization service."""
        log.debug("callback")
        try:
            token = self.get_token()
        except InsecureTransportError as e:
            log.warn(f"Error in getting token: {e}")
            helpers.flash_error("Authentication error; please contact the administrator.")
            return toolkit.redirect_to("/")

        try:
            user_name = self.authenticate(token)
        except InsecureTransportError as e:
            log.warn(f"Error authenticating user: {e}")
            helpers.flash_error("Authentication error; please contact the administrator.")
            return toolkit.redirect_to("/")

        # create headers from remember token to be added to redirected response
        remember_headers = self.remember(user_name)

        self.update_token(user_name, token)
        state = toolkit.request.params.get("state")
        redirect = toolkit.redirect_to(get_came_from(state))

        for header, value in remember_headers:
            redirect.headers[header] = value

        return redirect

    def identify(self):
        log.debug("identify")

        def _refresh_and_save_token(user_name):
            new_token = self.refresh_token(user_name)
            if new_token:
                toolkit.g.usertoken = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(self.authorization_header, "")
        user_name = None

        if self.authorization_header == "authorization":
            if apikey.startswith("Bearer "):
                apikey = apikey[7:].strip()
            else:
                apikey = ""

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {"access_token": apikey}
                user_name = self.authenticate(token)
            except Exception:
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and "repoze.who.identity" in environ:
            user_name = environ["repoze.who.identity"]["repoze.who.userid"]
            log.info(f"User {user_name} logged using session")
        # If we have been able to log in the user (via API or Session)
        if user_name:
            g.user = user_name
            toolkit.g.user = user_name
            toolkit.g.usertoken = self.get_stored_token(user_name)
            toolkit.g.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            log.warn("The user is not currently logged in...")

    def get_token(self):
        """Get token from authorization service."""
        log.debug("get_token")
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)

        try:
            # NOTE: authorization_response/toolkit.request.url was using http instead of https
            # hacked to replace http with https
            authorization_response = toolkit.request.url
            authorization_response = authorization_response.replace("http", "https")
            token = oauth.fetch_token(
                self.token_endpoint,
                client_secret=self.client_secret,
                authorization_response=authorization_response,
                verify=self.verify_https,
            )
        except InsecureTransportError:
            raise

        return token

    def authenticate(self, token):
        log.debug("authenticate")

        if self.jwt_enable:
            access_token = token["access_token"]
            user_data = jwt.decode(access_token, verify=False)
            user = self.user_json(user_data)
        else:

            try:
                oauth = OAuth2Session(self.client_id, token=token)
                profile_response = oauth.get(self.profile_api_url, verify=self.verify_https)
            except InsecureTransportError:
                raise

            # Token can be invalid
            if not profile_response.ok:
                error = profile_response.json()
                if error.get("error", "") == "invalid_token":
                    raise ValueError(error.get("error_description"))
                else:
                    profile_response.raise_for_status()
            else:
                user_data = profile_response.json()
                user = self.user_json(user_data)

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        return user.name

    def user_json(self, user_data):
        email = user_data[self.profile_api_mail_field]
        user_name = user_data[self.profile_api_user_field]

        # In CKAN can exists more than one user associated with the same email
        # Some providers, like Google and FIWARE only allows one account per email
        user = None
        users = model.User.by_email(email)
        if len(users) == 1:
            user = users[0]

        # If the user does not exist, we have to create it...
        if user is None:
            user = model.User(email=email)

        # Now we update his/her user_name with the one provided by the OAuth2 service
        # In the future, users will be obtained based on this field
        user.name = user_name

        # Update fullname
        if self.profile_api_fullname_field != "" and self.profile_api_fullname_field in user_data:
            user.fullname = user_data[self.profile_api_fullname_field]

        # Update sysadmin status
        if (
            self.profile_api_groupmembership_field != ""
            and self.profile_api_groupmembership_field in user_data
        ):
            user.sysadmin = (
                self.sysadmin_group_name in user_data[self.profile_api_groupmembership_field]
            )

        return user

    def _get_rememberer(self, environ):
        plugins = environ.get("repoze.who.plugins", {})
        return plugins.get(self.rememberer_name)

    def remember(self, user_name):
        """
        Remember the authenticated identity.

        This method simply delegates to another IIdentifier plugin if configured.

        Return headers so they can be added to redirected response.
        """
        log.debug("Repoze OAuth remember")
        environ = toolkit.request.environ
        rememberer = self._get_rememberer(environ)
        identity = {"repoze.who.userid": user_name}
        headers = rememberer.remember(environ, identity)

        return headers

    def get_stored_token(self, user_name):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                "access_token": user_token.access_token,
                "refresh_token": user_token.refresh_token,
                "expires_in": user_token.expires_in,
                "token_type": user_token.token_type,
            }

    def update_token(self, user_name, token):
        user_token = db.UserToken.by_user_name(user_name=user_name)

        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name

        # Save the new token
        user_token.access_token = token["access_token"]
        user_token.token_type = token["token_type"]
        user_token.refresh_token = token.get("refresh_token")
        if "expires_in" in token:
            user_token.expires_in = token["expires_in"]
        else:
            access_token = jwt.decode(user_token.access_token, verify=False)
            user_token.expires_in = access_token["exp"] - access_token["iat"]

        model.Session.add(user_token)
        model.Session.commit()

    def refresh_token(self, user_name):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            try:
                token = client.refresh_token(
                    self.token_endpoint,
                    client_secret=self.client_secret,
                    client_id=self.client_id,
                    verify=self.verify_https,
                )
            except InsecureTransportError:
                raise
            self.update_token(user_name, token)
            log.info(f"Token for user {user_name} has been updated properly")
            return token
        else:
            log.warn(f"User {user_name} has no refresh token")
