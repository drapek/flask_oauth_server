import ssl

from flask import Flask, url_for, session, request, jsonify, render_template
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
        errors = []
        email = username = address = 'Not fetched from server.'
        resp_email = remote.get('/api/email')
        if resp_email.status == 200:
            username = resp_email.data.get('username', 'not specified')
            email = resp_email.data.get('email', 'not specified')

        else:
            errors.append('/api/email returned {}'.format(resp_email.status))

        resp_address = remote.get('/api/address')
        if resp_address.status == 200:
            address = resp_address.data.get('address', 'not specified')
        else:
            errors.append('/api/email returned {}'.format(resp_address.status))

        return render_template('home.html', errors=errors, username=username, email=email, address=address)

    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True), state='STATE-drapek'
    )


@app.route('/authorized')
def authorized():
    # TODO here should be state checker to improve app safety
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
    ssl._create_default_https_context = ssl._create_unverified_context
    app.run(host='localhost', port=8000, ssl_context='adhoc')
