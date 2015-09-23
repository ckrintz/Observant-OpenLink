import json, flask, httplib2, webbrowser, traceback, requests, sys, uuid
from datetime import datetime, timedelta
#Google APIs OAuth2 library: pip install --upgrade google-api-python-client
from oauth2client import client
from oauth2client.file import Storage
import logging

app = flask.Flask(__name__)

#from https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
auth_url= 'https://test.obsrv.it/uaa/oauth/authorize'
token_url = 'https://test.obsrv.it/uaa/oauth/token'
api_url='https://test.obsrv.it/api/bookmarks'
service='TestFarms' 
sec='YYY' #contact jonathan.harvey@observant.net for this

obs_scope='sensor-data'
app_name = 'ObsServ'
#this is set in intialize_storage which must be run before all else, app entry is /
storage = None
#this is set in main and must map to app.run in main
redir = None

#You will also need a login and password for the test account 
#Contact jonathan.harvey@observant.net for these

################ initialize_storage ##################
def initialize_storage():
  '''
  Utility to grab the credentials from storage if any
  -- from https://developers.google.com/api-client-library/python/guide/aaa_oauth
  '''
  global storage
  fname = '{0}_{1}'.format(app_name,service)
  storage = Storage(fname)
  credentials = storage.get()
  if credentials is not None:
      flask.session['credentials'] = client.OAuth2Credentials.to_json(credentials)
      return True
  return False
    

################ refresh_creds ##################
def refresh_creds():

    '''
    Utility to manually refresh OAuth2 access_token.
    Refresh is currently valid six months from Observant OpenLink. 9/23/15
    '''
    global storage
    print 'Token has expired... refreshing'

    ''' 
    Perform the refresh.
    creds is guaranteed not to be None here given caller.
    '''
    creds = json.loads(flask.session['credentials']) 
    payload = {'grant_type':creds['refresh_token'], 
        'client_id':creds['client_id'], 
        'redirect_uri':redir}
    r = requests.post(creds['token_uri'], params=payload)
    res = r.json()
    if 'error' in res:
        print 'refresh error: {0}'.format(res['error'])
        ''' any error that occurs in the refresh process will result in restarting the protocol.
            Protocol restart (oauth2callback) requires the user/customer to reauthorize our
            use of their account '''
        return flask.redirect(flask.url_for('oauth2callback'))


    ''' 
    Create a new creds object and save it off on disk for fast access.
    Note that the object saved on disk is clear text and contains the secret.
    '''
    credentials = client.OAuth2Credentials(access_token=res['access_token'],
        client_id=creds['client_id'],
        client_secret=creds['client_secret'],
        refresh_token=creds['refresh_token'],
        token_expiry=datetime.now()+timedelta(seconds=res['expires_in']),
        token_uri=creds['token_uri'],user_agent=creds['user_agent'])
    if storage is None:
        fname = '{0}_{1}'.format(app_name,service)
        storage = Storage(fname)
    storage.put(credentials)
    flask.session['credentials'] = client.OAuth2Credentials.to_json(credentials)

    #redirect to / 
    return flask.redirect(flask.url_for('index'))


################ index route ##################
@app.route('/',strict_slashes=False)
def index():

    '''
    This function is invoked to access the Observant OpenLink API.
    It currently queries the https://test.obsrv.it/api/bookmarks
    For more information on the API see: 
    https://github.com/ObservantPtyLtd/oada-client/blob/master/API.md
    '''

    '''
    If there are no credentials, redirect to oauth2callback to get them, requiring
    user login and authorization.
    '''
    if 'credentials' not in flask.session:
        #check first to see if we have valid credentials stored away from a previous run
        if not initialize_storage():
            return flask.redirect(flask.url_for('oauth2callback'))

    '''
    If there are credentials, but the access token has expired, it calls
    refresh_creds to refresh the token. When the refresh token expires, this call
    will ultimately route to oauth2callback which regenerate both tokens, requiring
    user login and authorization.
    creds is guaranteed not to be None here given the check above.
    '''
    creds = json.loads(flask.session['credentials']) #json
    exp = datetime.strptime(creds['token_expiry'], '%Y-%m-%dT%H:%M:%SZ')
    dtn = datetime.now()

    ''' 
    From Observant 9/7/14: access token will have a validity of 2 weeks (it was originally 24 hrs) 
    '''
    mins = 24*60*14
    if exp < dtn:
        print 'token has expired'   
        #Manual refresh of the token
        refresh_creds() 
    else:
        #avoiding use of total_seconds() so this works for python 2.6 and 2.7
        diff = (exp-dtn)
        mins = diff.days * 1440 + diff.seconds//60
        print 'token will expire in {0} minutes'.format(mins)
  
    '''
    This is where we put the access_token and/or request on a queue and have it periodically 
    request data.  For now we just access the API and dump json result to the console. 
    '''
    header = {'Authorization': 'Bearer {0}'.format(creds['access_token'])}
    r = None
    try:
        r = requests.get(api_url, headers=header)
    except requests.exceptions.RequestException as e:  
        print e
        return 'Observant API access failed: {0}'.format(e)
    if r is not None:
	#This is where we insert the code for storing the data that comes back from the request
        print r.text
    '''
    The following can be updated to display a better website or route elsewhere
    Then this entire method can be performed in the background on a periodic basis
    '''
    return 'Observant API access succeeded: TTL={0} mins'.format(mins)


################ oauth2 callback route ##################
@app.route('/testfarms/oada', strict_slashes=False)  #required by Observant testing environment
@app.route('/smartfarm/oada', strict_slashes=False)  #required by Observant testing environment
def oauth2callback():
    '''
    This method uses the Google oauth2callback library to perform the OAuth2 handshake.
    Because Observant uses a non-standard approach to code-token exchange, step2_exchange
    cannot be used directly.  Details below.
    '''
    global storage

    #print auth_url, token_url
    try:
        #from https://developers.google.com/identity/protocols/OAuth2WebServer
        flow = client.OAuth2WebServerFlow(
            client_id=service,
            client_secret=sec,
            scope=obs_scope,
            redirect_uri=redir,
            auth_uri=auth_url,
            token_uri=token_url,
            include_granted_scopes=True)
    except: 
        print traceback.format_exc()

    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        credentials = None

    ''' WORK AROUND #1 ------------------------
        The following returns unauthorized as if the appropriate headers 
            or full url (username,pwd) is not being passed correctly.
	    Likely due to non-standard OAuth2 implementation on Observant side

           From Jon/Observant 9/7/15:
           Also, on closer inspection it seems that Basic Auth security is being applied to our OAuth endpoints which is resulting in the non-OAuth2-standard token exchange you rightly point out. This is something that we will also be looking to resolve. For the moment, though, we will have to ask that you continue to provide the client ID and client secret as Basic Auth credentials when using those endpoints. We will notify you when this is about to change... for now the documentation in the repo gives an example of how to do this, albeit with the additional Basic Auth on the token endpoint.

           Instead we send the complete payload (Basic Auth credentials) below
    try:
        credentials = flow.step2_exchange(auth_code)
    except client.FlowExchangeError, e:
        print 'Authentication failed: {0}'.format(e)
    ----------------------------------------'''

    #Using Basic Auth with client ID and secret
    payload = {'grant_type':'authorization_code', 
        'client_id':service, 
        'redirect_uri':redir, 
        'code':auth_code }
    r = requests.post(token_url, params=payload)
    res = r.json()

    credentials = client.OAuth2Credentials(access_token=res['access_token'],
        client_id=service,
        client_secret=sec,
        refresh_token=res['refresh_token'],
        token_expiry=datetime.now()+timedelta(seconds=res['expires_in']),
        token_uri=token_url,
        user_agent='testfarms v1.0') 
    if storage is None:
        fname = '{0}_{1}'.format(app_name,service)
        storage = Storage(fname)
    storage.put(credentials)
    flask.session['credentials'] = client.OAuth2Credentials.to_json(credentials)
    return flask.redirect(flask.url_for('index'))

if __name__ == '__main__':

    logging.basicConfig()

    #read in the credentials (service and secret) from simple json file
    try: 
        with open('creds.json') as data_file:    
            data = json.load(data_file)
            service = data['service']
            sec = data['secret']
    except:
        print 'Error accessing creds.json file or with its file format.  It must contain the keys service and secret and be in the same directory as this program.'
        sys.exit(1)
        

    '''
    WORK AROUND (part of #1 above) for obtaining Observant tokens: 
    see for details: https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
    '''
    token_url = 'https://{serv}:{sec}@test.obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)


    #start the flask server
    app.secret_key = str(uuid.uuid4())
    app.debug = False

    if len(sys.argv) > 1: #production/IP setting
        print 'creating production server'
        #alternative setup from a real server, once registered with Observant (including redirects)
        redir='http://XXX.XXX.XXX.XXX:PORT/myroute/oada/' #in main, use app.run(host='0.0.0.0',port=8088)
        app.run(host='0.0.0.0',port=PORT)
    else:  #test/localhost
        #this is the only supported redirect for the Observant test account
        print 'creating test server'
        redir='http://localhost:9977/testfarms/oada/'  #in main, use app.run(host='localhost',port=9977)
        app.run(host='localhost',port=9977)
