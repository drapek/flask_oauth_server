from requests_oauthlib import OAuth2Session

oauth = OAuth2Session('dev', redirect_uri='https://localhost:8000', scope=['email'])
print('oauth: ', oauth)

auth_url, state = oauth.authorization_url('https://localhost:8000/')
print('auth_url: ', auth_url, '\nstate: ', state)

auth_response = input('Please insert your auth url response:')

token = oauth.fetch_token('https://localhost:8000/oauth/token', authorization_response=auth_response,
                          client_secret='dev')
print('token: ', token)

