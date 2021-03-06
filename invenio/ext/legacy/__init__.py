# -*- coding: utf-8 -*-
#
## This file is part of Invenio.
## Copyright (C) 2011, 2012, 2013, 2014 CERN.
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

import warnings

from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.wrappers import BaseResponse

from flask import request, g, current_app, render_template, abort, \
    safe_join, send_from_directory

from .request_class import LegacyRequest


def setup_app(app):
    """Setup up the app."""
    # Legacy config support
    USE_X_SENDFILE = app.config.get('CFG_BIBDOCFILE_USE_XSENDFILE')
    DEBUG = app.config.get('CFG_DEVEL_SITE', 0) > 0
    app.config.setdefault('USE_X_SENDFILE', USE_X_SENDFILE)
    app.config.setdefault('DEBUG', DEBUG)
    app.debug = app.config['DEBUG']

    class LegacyAppMiddleware(object):

        def __init__(self, app):
            self.app = app

        def __call__(self, environ, start_response):
            with self.app.request_context(environ):
                g.start_response = start_response
                try:
                    response = self.app.full_dispatch_request()
                except Exception as e:
                    from invenio.ext.logging import register_exception
                    register_exception(req=request, alert_admin=True)
                    response = self.app.handle_exception(e)

                return response(environ, start_response)

    # Set custom request class.
    app.request_class = LegacyRequest
    app.wsgi_app = LegacyAppMiddleware(app)

    @app.errorhandler(404)
    @app.errorhandler(405)
    def page_not_found(error):
        try:
            from invenio.legacy.wsgi import \
                application as legacy_application
            response = legacy_application(request.environ, g.start_response)
            if not isinstance(response, BaseResponse):
                response = current_app.make_response(str(response))
            return response
        except HTTPException:
            from flask import current_app
            # FIXME: check if request.path is static
            try:
                return current_app.send_static_file(request.path)
            except NotFound as e:
                current_app.logger.info(str(e) + " " + request.path)
                error = e
        if error.code == 404:
            return render_template('404.html'), 404
        return str(error), error.code

    @app.route('/admin/<module>/<action>.py', methods=['GET', 'POST', 'PUT'])
    @app.route('/admin/<module>/<action>.py/<path:arguments>',
               methods=['GET', 'POST', 'PUT'])
    def web_admin(module, action, arguments=None):
        """
        Adds support for legacy mod publisher.
        """
        from invenio.legacy.wsgi import \
            is_mp_legacy_publisher_path, mp_legacy_publisher, \
            application as legacy_application
        possible_module, possible_handler = is_mp_legacy_publisher_path(
            request.environ['PATH_INFO'])
        if possible_module is not None:
            legacy_publisher = lambda req: \
                mp_legacy_publisher(req, possible_module, possible_handler)
            return legacy_application(request.environ, g.start_response,
                                      handler=legacy_publisher)
        return render_template('404.html'), 404

    @app.endpoint('static')
    def static_handler_with_legacy_publisher(*args, **kwargs):
        """
        Serves static files from instance path.
        """
        # Static file serving for devserver
        # ---------------------------------
        # Apache normally serve all static files, but if we are using the
        # devserver we need to serve static files here.
        if not app.config.get('CFG_FLASK_SERVE_STATIC_FILES'):
            abort(404)
        else:
            try:
                static_file_response = app.send_static_file(*args, **kwargs)
            except NotFound:
                static_file_response = send_from_directory(
                    safe_join(app.instance_path, 'static'), kwargs['filename'])
            return static_file_response

    try:
        # pylint: disable=E0611
        from invenio.webinterface_handler_local import customize_app  # noqa
        # pylint: enable=E0611
        warnings.warn("Do not use 'invenio.webinterface_handler_local:"
                      "customize_app' directly. Please, adapt your function "
                      "into package and use configuration option "
                      "EXTENSIONS = ['mypackage.customize_app'] instead.",
                      DeprecationWarning)
    except ImportError:
        pass

    return app
