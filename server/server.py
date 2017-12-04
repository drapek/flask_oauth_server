# coding: utf-8
import logging
from bcrypt import checkpw
from urllib.parse import quote
from datetime import datetime, timedelta
from flask import g, render_template, request, jsonify, make_response, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.oauth2 import bind_sqlalchemy
from flask_oauthlib.contrib.oauth2 import bind_cache_grant


db = SQLAlchemy()
log = logging.getLogger('flask_oauthlib')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, index=True,
                         nullable=False)
    address = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    real_name = db.Column(db.String(120), nullable=False)
    encrypted_password = db.Column(db.String(60), nullable=False)

    def check_password(self, password):
        return checkpw(password.encode('utf-8'), self.encrypted_password.encode('utf-8'))


class Client(db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    # human readable name
    name = db.Column(db.String(40))
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.String(20), default='public')
    _redirect_uris = db.Column(db.Text)
    default_scope = db.Column(db.Text, default='email address real_name')

    @property
    def user(self):
        return User.query.get(1)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self.default_scope:
            return self.default_scope.split()
        return []

    @property
    def allowed_grant_types(self):
        return ['authorization_code', 'token', 'refresh_token']


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    scope = db.Column(db.Text)
    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')
    client = relationship('Client')
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.Text)

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in', None)
        if expires_in is not None:
            self.expires = datetime.utcnow() + timedelta(seconds=expires_in)

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self


def current_user():
    return g.user


def cache_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User,
                    token=Token, client=Client)

    app.config.update({'OAUTH2_CACHE_TYPE': 'simple'})
    bind_cache_grant(app, oauth, current_user)
    return oauth


def sqlalchemy_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User, token=Token,
                    client=Client, grant=Grant, current_user=current_user)

    return oauth


def default_provider(app):
    oauth = OAuth2Provider(app)

    @oauth.clientgetter
    def get_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    @oauth.grantgetter
    def get_grant(client_id, code):
        return Grant.query.filter_by(client_id=client_id, code=code).first()

    @oauth.tokengetter
    def get_token(access_token=None, refresh_token=None):
        if access_token:
            return Token.query.filter_by(access_token=access_token).first()
        if refresh_token:
            return Token.query.filter_by(refresh_token=refresh_token).first()
        return {}

    @oauth.grantsetter
    def set_grant(client_id, code, request, *args, **kwargs):
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id=g.user.id,
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        # In real project, a token is unique bound to user and client.
        # Which means, you don't need to create a token every time.
        tok = Token(**token)
        tok.user_id = request.user.id if request.user else session.get('user_id', None)
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        return User.query.filter_by(username=username).first()

    return oauth


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    if User.query.count() is not 0:
        return app

    client1 = Client(
        name='dev', client_id='dev', client_secret='dev',
        _redirect_uris=(
            'https://localhost:20444/authorized'
        ),
    )

    client2 = Client(
        name='confidential', client_id='confidential',
        client_secret='confidential', client_type='confidential',
        _redirect_uris=(
            'https://localhost:20444/authorized'
        ),
    )

    admin = User(username='admin', encrypted_password='$2b$12$O0PRNPdSdMcLWNUivIiAl.UUVjqvEWa1YxfFIhqUzVaI7NgZ7.cL.',
                 email='admin@edu.pl', real_name='', address='Koszykowa 75')
    alice = User(username='alice', encrypted_password='$2b$12$SkOiWN4CzoRVAsoIi6G9D.xdHi.1vTWQ4SbYRjwX87asUZ9gj3yOu',
                 email='alice@edu.pl', real_name='Alice Wonderland', address='Wonderland')
    bob = User(username='bob',   encrypted_password='$2b$12$1Hk7FV7zRK3Qfhr0zWMVz.ZXqDw8HRuDr3HdRl73ullJW5gxULZuq',
               email='bob@edu.pl', real_name='Bob Builder', address='Radom')

    try:
        db.session.add(admin)
        db.session.add(alice)
        db.session.add(bob)
        db.session.add(client1)
        db.session.add(client2)
        db.session.commit()
    except Exception as e:
        print('Error while creating the database')
        print(e)
        db.session.rollback()
    return app


def create_server(application, oauth=None):
    if not oauth:
        oauth = default_provider(application)
    application = prepare_app(application)

    @application.before_request
    def load_current_user():
        if 'user_id' not in session:
            g.user = None
        else:
            user = User.query.get(session['user_id'])
            g.user = user

    @application.route('/home')
    def home():
        return render_template('home.html')

    @application.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html')
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('errors.html', error=[u'Provide both username and password'])
        query = User.query.filter_by(username=username)
        user = None if query.count() is not 1 else query.one()
        valid = False if user is None else user.check_password(password)
        if not valid:
            return render_template('errors.html', error=[u'Incorrect username or password'])
        session['user_id'] = user.id
        if 'redirect' in request.args:
            return redirect(request.args.get('redirect'))
        return redirect(url_for('home'))

    @application.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @application.route('/oauth/errors')
    def errors(*args, **kwargs):
        return render_template('errors.html', **request.args)

    @application.route('/oauth/authorize', methods=['GET', 'POST'])
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login?redirect='+quote(request.url))
        # NOTICE: for real project, you need to require login
        if request.method == 'GET':
            # render a page for user to confirm the authorization
            scopes = kwargs.get('scopes')
            client = Client.query.get(kwargs.get('client_id'))
            return render_template('confirm.html', scopes=scopes, client=client.name)

        if request.method == 'HEAD':
            # if HEAD is supported properly, request parameters like
            # client_id should be validated the same way as for 'GET'
            response = make_response('', 200)
            response.headers['X-Client-ID'] = kwargs.get('client_id')
            return response

        confirm = request.form.get('confirm', 'no')
        return confirm == 'yes'

    @application.route('/oauth/token', methods=['POST', 'GET'])
    @oauth.token_handler
    def access_token():
        return {}

    @application.route('/oauth/revoke', methods=['POST'])
    @oauth.revoke_handler
    def revoke_token():
        pass

    @application.route('/api/email')
    @oauth.require_oauth('email')
    def email_api():
        oauth = request.oauth
        return jsonify(email=oauth.user.email, username=oauth.user.username)

    @application.route('/api/real_name')
    @oauth.require_oauth('real_name')
    def real_name_api():
        oauth = request.oauth
        return jsonify(email=oauth.user.real_name, username=oauth.user.username)

    @application.route('/api/client')
    @oauth.require_oauth()
    def client_api():
        oauth = request.oauth
        return jsonify(client=oauth.client.real_name)

    @application.route('/api/address')
    @oauth.require_oauth('address')
    def address_api():
        oauth = request.oauth
        return jsonify(address=oauth.user.address, username=oauth.user.username)

    @application.route('/api/method', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @oauth.require_oauth()
    def method_api():
        return jsonify(method=request.method)

    @oauth.invalid_response
    def require_oauth_invalid(req):
        return jsonify(message=req.error_message), 401

    return application


if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///test.sqlite'
    })
    app = create_server(app)
    app.run(port=20443, ssl_context='adhoc')
