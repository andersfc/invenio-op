# -*- coding: utf-8 -*-
##
## This file is part of Invenio.
## Copyright (C) 2014 CERN.
##
## Invenio is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 2 of the
## License, or (at your option) any later version.
##
## Invenio is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with Invenio; if not, write to the Free Software Foundation, Inc.,
## 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

"""
OAuth 2.0 Provider
"""

from __future__ import absolute_import

import os

from flask import Blueprint, current_app, request, render_template, jsonify, \
    abort
from flask_oauthlib.contrib.oauth2 import bind_cache_grant, bind_sqlalchemy
from flask.ext.login import login_required
from flask.ext.breadcrumbs import register_breadcrumb

from invenio.ext.sqlalchemy import db
from invenio.ext.login import login_user
from invenio.base.i18n import _

from ..provider import oauth2
from ..models import Client, OAuthUserProxy
from ..registry import scopes as scopes_registry


blueprint = Blueprint(
    'oauth2server',
    __name__,
    url_prefix='/oauth',
    static_folder="../static",
    template_folder="../templates",
)


@blueprint.before_app_first_request
def setup_app():
    """
    Setup OAuth2 provider
    """
    # Initialize OAuth2 provider
    oauth2.init_app(current_app)

    # Configures the OAuth2 provider to use the SQLALchemy models for getters
    # and setters for user, client and tokens.
    bind_sqlalchemy(oauth2, db.session, client=Client)

    # Configures an OAuth2Provider instance to use configured caching system
    # to get and set the grant token.
    bind_cache_grant(current_app, oauth2, OAuthUserProxy.get_current_user)

    # Disables oauthlib's secure transport detection in in debug mode.
    if current_app.debug:
        os.environ['DEBUG'] = '1'


@oauth2.after_request
def login_oauth2_user(valid, oauth):
    """
    Login a user after having been verified
    """
    if valid:
        login_user(oauth.user.id)
    return valid, oauth


#
# Views
#
@blueprint.route('/authorize', methods=['GET', 'POST'])
@register_breadcrumb(blueprint, '.', _('Authorize application'))
@login_required
@oauth2.authorize_handler
def authorize(*args, **kwargs):
    """
    View for rendering authorization request.
    """
    if request.method == 'GET':
        client = Client.query.filter_by(
            client_id=kwargs.get('client_id')
        ).first()

        if not client:
            abort(404)

        ctx = dict(
            client=client,
            oauth_request=kwargs.get('request'),
            scopes=map(lambda x: scopes_registry[x], kwargs.get('scopes', []))
        )
        return render_template('oauth2server/authorize.html', **ctx)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@blueprint.route('/token', methods=['POST', ])
@oauth2.token_handler
def access_token():
    """
    Token view handles exchange/refresh access tokens
    """
    return {}


@blueprint.route('/errors')
def errors():
    """
    Error view in case of invalid oauth requests
    """
    return render_template('oauth2server/errors.html')


@blueprint.route('/ping/')
@oauth2.require_oauth()
def ping(oauth_request):
    """
    Test to verify that you have been authenticated.
    """
    return jsonify(dict(ping="pong"))


@blueprint.route('/info/')
@oauth2.require_oauth('user')
def info(oauth_request):
    """
    Test to verify that you have been authenticated.
    """
    if current_app.debug:
        return jsonify(dict(
            user=oauth_request.user.id,
            client=oauth_request.client.client_id,
            scopes=list(oauth_request.scopes),
        ))
    else:
        abort(404)


@blueprint.route('/invalid/')
@oauth2.require_oauth('invalid_scope')
def invalid(oauth_request):
    """
    Test to verify that you have been authenticated.
    """
    if current_app.debug:
        # Not reachable
        return jsonify(dict(ding="dong"))
    else:
        abort(404)
