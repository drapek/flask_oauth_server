from OpenSSL import SSL
from flask import Flask, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth


CLIENT_ID = 'dev'
CLIENT_SECRET = 'dev'


app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

remote = oauth.remote_app(
    'dev',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': 'email address'},  # TODO address real_name
    base_url='https://127.0.0.1:8888/login',
    request_token_url=None,
    access_token_url='https://127.0.0.1:8888/oauth/token',
    authorize_url='https://127.0.0.1:8888/oauth/authorize'
)


@app.route('/')
def index():
    if 'remote_oauth' in session:
        resp = remote.get('me')
        return jsonify(resp.data)
    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )


@app.route('/authorized')
def authorized():
    resp = remote.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    print(resp)
    session['remote_oauth'] = (resp['access_token'], '')
    return jsonify(oauth_token=resp['access_token'])


@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    # context = SSL.Context(SSL.SSLv23_METHOD)
    # context.use_privatekey_file('client.key')
    # context.use_certificate_file('client.crt')
    context = ('client.crt', 'client.key')
    app.run(host='localhost', port=8000, ssl_context=context)  # originally ssl_context='adhoc'
