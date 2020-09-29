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

from functools import partial
import logging
import os
from urllib.parse import urlparse

from flask import Blueprint, redirect, request

from ckan import plugins
from ckan.common import g, session
from ckan.lib import helpers
from ckan.plugins import toolkit

from ckanext.oauth2 import constants, oauth2

log = logging.getLogger(__name__)


def _no_permissions(context, msg):
    user = context["user"]
    return {"success": False, "msg": msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._("Users cannot be created.")
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._("Users cannot be edited.")
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._("Users cannot reset passwords.")
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._("Users cannot reset passwords.")
    return _no_permissions(context, msg)


def _get_previous_page(default_page):
    if "came_from" not in toolkit.request.params:
        came_from_url = toolkit.request.headers.get("Referer", default_page)
    else:
        came_from_url = toolkit.request.params.get("came_from", default_page)

    came_from_url_parsed = urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if came_from_url_parsed.netloc != "" and came_from_url_parsed.netloc != toolkit.request.host:
        came_from_url = default_page

    # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
    # he/she must be redirected to the dashboard
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

        self.oauth2helper = oauth2.OAuth2Helper()

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
        blueprint = Blueprint("oauth2", self.__module__)
        rules = [
            ("/user/login", "login", self.login),
            ("/oauth2/callback", "callback", self.callback),
        ]

        for rule in rules:
            blueprint.add_url_rule(*rule)

        return blueprint

    def login(self):
        log.debug("login")
        print("hello from plugin.py login()")

        # Log in attemps are fired when the user is not logged in and they click
        # on the log in button

        # Get the page where the user was when the loggin attemp was fired
        # When the user is not logged in, he/she should be redirected to the dashboard when
        # the system cannot get the previous page
        came_from_url = _get_previous_page(constants.INITIAL_PAGE)

        self.oauth2helper.challenge(came_from_url)

    def callback(self):
        try:
            token = self.oauth2helper.get_token()
            user_name = self.oauth2helper.identify(token)
            self.oauth2helper.remember(user_name)
            self.oauth2helper.update_token(user_name, token)
            self.oauth2helper.redirect_from_callback()
        except Exception as e:

            session.save()

            # If the callback is called with an error, we must show the message
            error_description = toolkit.request.GET.get("error_description")
            if not error_description:
                if e.message:
                    error_description = e.message
                elif hasattr(e, "description") and e.description:
                    error_description = e.description
                elif hasattr(e, "error") and e.error:
                    error_description = e.error
                else:
                    error_description = type(e).__name__

            toolkit.response.status_int = 302
            redirect_url = oauth2.get_came_from(toolkit.request.params.get("state"))
            redirect_url = "/" if redirect_url == constants.INITIAL_PAGE else redirect_url
            toolkit.response.location = redirect_url
            helpers.flash_error(error_description)

    def identify(self):
        log.debug("identify")
        print("hello from plugin.py identify()")

        def _refresh_and_save_token(user_name):
            new_token = self.oauth2helper.refresh_token(user_name)
            print("new_token: ", new_token)
            if new_token:
                # toolkit.c.usertoken = new_token
                toolkit.g.usertoken = new_token

        environ = toolkit.request.environ
        print("environ: ", environ)
        print("toolkit.request.headers: ", toolkit.request.headers)
        # apikey = toolkit.request.headers.get(self.authorization_header, "")
        apikey = request.headers.get(self.authorization_header, "")
        user_name = None
        print("authorization header: ", self.authorization_header)

        if self.authorization_header == "authorization":
            print("here")
            if apikey.startswith("Bearer "):
                apikey = apikey[7:].strip()
            else:
                apikey = ""

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {"access_token": apikey}
                user_name = self.oauth2helper.identify(token)
            except Exception:
                pass

        print("apikey: ", apikey)

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and "repoze.who.identity" in environ:
            user_name = environ["repoze.who.identity"]["repoze.who.userid"]
            log.info("User %s logged using session" % user_name)
        # If we have been able to log in the user (via API or Session)
        if user_name:
            g.user = user_name
            # toolkit.c.user = user_name
            # toolkit.c.usertoken = self.oauth2helper.get_stored_token(user_name)
            # toolkit.c.usertoken_refresh = partial(_refresh_and_save_token, user_name)
            toolkit.g.user = user_name
            toolkit.g.usertoken = self.oauth2helper.get_stored_token(user_name)
            toolkit.g.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            log.warn("The user is not currently logged...")

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            "user_create": user_create,
            "user_update": user_update,
            "user_reset": user_reset,
            "request_reset": request_reset,
        }

    def update_config(self, config):
        # Update our configuration
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

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, "templates")
