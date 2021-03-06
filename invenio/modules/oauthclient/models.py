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


from sqlalchemy.ext.mutable import MutableDict
from invenio.modules.accounts.models import User
from invenio.ext.sqlalchemy import db


class RemoteAccount(db.Model):
    """
    Storage for remote linked accounts
    """

    __tablename__ = 'remoteACCOUNT'

    __table_args__ = (
        db.UniqueConstraint('user_id', 'client_id'),
        db.Model.__table_args__
    )

    #
    # Fields
    #
    id = db.Column(
        db.Integer(15, unsigned=True),
        primary_key=True,
        autoincrement=True
    )
    """ Primary key """

    user_id = db.Column(
        db.Integer(15, unsigned=True),
        db.ForeignKey(User.id),
        nullable=False
    )
    """ Local user linked with a remote app via the access token"""

    client_id = db.Column(db.String(255), nullable=False)
    """ Client ID of remote application (defined in OAUTHCLIENT_REMOTE_APPS)"""

    extra_data = db.Column(MutableDict.as_mutable(db.JSON), nullable=False)
    """ Extra data associated with this linked account """

    #
    # Relationships propoerties
    #
    user = db.relationship('User')
    """ SQLAlchemy relationship to user """

    tokens = db.relationship(
        "RemoteToken",
        backref="remote_account",
    )
    """ SQLAlchemy relationship to RemoteToken objects """

    @classmethod
    def get(cls, user_id, client_id):
        """
        Method to get RemoteAccount object for user
        """
        return cls.query.filter_by(
            user_id=user_id,
            client_id=client_id,
        ).first()

    @classmethod
    def create(cls, user_id, client_id, extra_data):
        account = cls(
            user_id=user_id,
            client_id=client_id,
            extra_data=extra_data or dict()
        )
        db.session.add(account)
        db.session.commit()
        return account

    def delete(self):
        """
        Delete remote account toegether with all stored tokens
        """
        RemoteToken.query.filter_by(id_remote_account=self.id).delete()
        db.session.delete(self)
        db.session.commit()


class RemoteToken(db.Model):
    """
    Storage for the access tokens for linked accounts
    """
    __tablename__ = 'remoteTOKEN'

    #
    # Fields
    #
    id_remote_account = db.Column(
        db.Integer(15, unsigned=True),
        db.ForeignKey(RemoteAccount.id),
        nullable=False,
        primary_key=True
    )
    """ Foreign key to account """

    token_type = db.Column(
        db.String(40), default='', nullable=False, primary_key=True
    )
    """ Type of token """

    access_token = db.Column(db.Text(), nullable=False)
    """ Access token to remote application """

    secret = db.Column(db.Text(), default='', nullable=False)
    """ Used only by OAuth 1 """

    def token(self):
        """
        Return token as expected by Flask-OAuthlib
        """
        return (self.access_token, self.secret)

    def update_token(self, token, secret):
        if self.access_token != token or self.secret != secret:
            self.access_token = token
            self.secret = secret
            db.session.commit()

    @classmethod
    def get(cls, user_id, client_id, token_type='', access_token=None):
        """
        Method to get RemoteToken for user
        """
        args = [
            RemoteAccount.id == RemoteToken.id_remote_account,
            RemoteAccount.user_id == user_id,
            RemoteAccount.client_id == client_id,
            RemoteToken.token_type == token_type,
        ]

        if access_token:
            args.append(RemoteToken.access_token == access_token)

        return cls.query.options(
            db.joinedload('remote_account')
        ).filter(*args).first()

    @classmethod
    def get_by_token(cls, client_id, access_token, token_type=''):
        """
        Method to get RemoteAccount object for token
        """
        return cls.query.options(db.joinedload('remote_account')).filter(
            RemoteAccount.id == RemoteToken.id_remote_account,
            RemoteAccount.client_id == client_id,
            RemoteToken.token_type == token_type,
            RemoteToken.access_token == access_token,
        ).first()

    @classmethod
    def create(cls, user_id, client_id, token, secret,
               token_type='', extra_data=None):
        """
        Create a new access token - if RemoteAccount doesn't exist create it
        as well.
        """
        account = RemoteAccount.get(user_id, client_id)

        if account is None:
            account = RemoteAccount(
                user_id=user_id,
                client_id=client_id,
                extra_data=extra_data or dict(),
            )
            db.session.add(account)

        token = cls(
            token_type=token_type,
            remote_account=account,
            access_token=token,
            secret=secret,
        )
        db.session.add(token)
        db.session.commit()
        return token
