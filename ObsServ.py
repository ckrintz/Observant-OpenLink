import json, flask, httplib2, webbrowser, traceback, requests, sys, uuid
from datetime import datetime, timedelta
#Google APIs OAuth2 library: pip install --upgrade google-api-python-client
from oauth2client import client
from oauth2client.file import Storage
import logging

app = flask.Flask(__name__)
DEBUG = False
TEST = False
testcount = 0

#from https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
auth_url= 'https://test.obsrv.it/uaa/oauth/authorize'
token_url = 'https://test.obsrv.it/uaa/oauth/token'
api_url='https://test.obsrv.it/api/bookmarks' #works
#api_url='https://test.obsrv.it/api/bookmark/sensors' #"status":404,"error":"Not Found"
api_url='https://test.obsrv.it/api/bookmarks' #works
api_url='https://test.obsrv.it/api/resources/davis/app-63bcecd2-719e-41b7-a198-9fbeee10f0c8/data' #works
#watermark test system
api_url='https://test.obsrv.it/api/resources/testfarms/app-0bc29b01-31cd-4820-908b-8c20b2e2989b/data'
service='TestFarms' 
sec='YYY' #contact openlink@observant.net for this, place in creds.json (not in repo!)

obs_scope='sensor-data'
app_name = 'ObsServ'
#this is set in intialize_storage which must be run before all else, app entry is /
storage = None
#this is set in main and must map to app.run in main
redir = None

#You will also need a login and password for the test account 
#Contact openlink@observant.net for these

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
      if DEBUG:
          print 'init_storage, got creds from storage: {0}'.format(credentials)
      return True
  if DEBUG:
      print 'init_storage, unable to get creds'
  return False
    

################ refresh_creds ##################
def refresh_creds():

    '''
    Utility to refresh OAuth2 access_token.
    Refresh is currently valid six months from Observant OpenLink. 9/23/15
    '''
    global storage
    print 'Token has expired... refreshing'

    ''' 
    Perform the refresh.
    creds is guaranteed not to be None here given caller.
    '''
    creds = json.loads(flask.session['credentials']) 
    payload = {'grant_type':'refresh_token', 
        'refresh_token':creds['refresh_token'],
        'client_id':creds['client_id'], 
        'client_secret':creds['client_secret'], 
        'redirect_uri':redir} 

    if DEBUG:
        print 'refresh payload: {0}\n\ttoken_uri {1}'.format(payload,creds['token_uri'])
    r = requests.post(creds['token_uri'], params=payload)
    res = r.json()
    if DEBUG:
        print 'result: {0}'.format(res)
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

    #redirect to /query 
    return flask.redirect(flask.url_for('query'))


################ query route ##################
@app.route('/query',strict_slashes=False)
def query():
    global testcount
    '''
    This function is invoked to access the Observant OpenLink API.
    It currently queries the url at api_url
    For more information on the API see: 
    https://github.com/ObservantPtyLtd/oada-client/blob/master/API.md
    '''
    if 'credentials' not in flask.session:
        #check first to see if we have valid credentials stored away from a previous run
        if not initialize_storage():
            return flask.redirect(flask.url_for('oauth2callback'))
    
    #for testing purposes only
    if TEST and testcount == 0:
        print 'in Test'
        testcount = 1 #avoid looping b/c refresh redirects to query
        refresh_creds()
	#session credentials is set by refresh_creds

    creds = json.loads(flask.session['credentials']) #json

    header = {'Authorization': 'Bearer {0}'.format(creds['access_token'])}
    r = None
    try:
        r = requests.get(api_url, headers=header)
    except requests.exceptions.RequestException as e:  
        print e
        return 'Observant API access failed: {0}'.format(e)

    if r is not None:
	#This is where we insert the code for storing the data that comes back from the request
	output = r.text
        if r.status_code == 401:  #unauthorized - check if refresh is needed, else regenerate from code
            refresh_creds()
            #do it again
            creds = json.loads(CLI_session['credentials']) #json
            header = {'Authorization': 'Bearer {0}'.format(creds['access_token'])}
            r = None
            try:
                r = requests.get(api_url, headers=header)
            except requests.exceptions.RequestException as e:  
                print 'API Access post refresh failed: {0}'.format(e)
                output = {'name':'api_access_post_refresh_failed'}
    else: 
        output = {'name':'api_access_failed'}
    if DEBUG:
        print 'request output: {0}'.format(output)

    '''
    The following can be updated to display a better website or route elsewhere
    Then this entire method can be performed in the background on a periodic basis
    '''
    return output


################ oauth2 callback route ##################
@app.route('/testfarms/oada', strict_slashes=False)  #required by Observant testing environment
@app.route('/smartfarm/oada', strict_slashes=False)  #required by Observant production environment
def oauth2callback():
    '''
    This method uses the Google oauth2callback library to perform the OAuth2 handshake.
    Because Observant uses a non-standard approach to code-token exchange, step2_exchange
    cannot be used directly.  Details below.
    '''
    global storage

    print 'Performing oauth2 web server flow'
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
        if DEBUG:
            print 'calling Oauth2 step 1'
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        credentials = None

    ''' WORK AROUND #1 ------------------------
        The following returns unauthorized as if the appropriate headers 
            or full url (username,pwd) is not being passed correctly.
	    Likely due to non-standard OAuth2 implementation on Observant side.
           Instead we send the complete payload (Basic Auth credentials)
    try:
        credentials = flow.step2_exchange(auth_code)
    except client.FlowExchangeError, e:
        print 'Authentication failed: {0}'.format(e)
    ----------------------------------------'''

    #Using Basic Auth with client ID and secret
    print 'Requesting creds via code (OAuth2 step 2)'
    payload = {'grant_type':'authorization_code', 
        'client_id':service, 
        'redirect_uri':redir, 
        'code':auth_code }
    if DEBUG:
        print 'basic auth payload: {0}'.format(payload)
        print 'basic auth url: {0}'.format(token_url)
    r = requests.post(token_url, params=payload)
    res = r.json()

    if DEBUG:
        print 'basic auth result from {0}: {1}'.format(r.url,res)
    credentials = client.OAuth2Credentials(access_token=res['access_token'],
        client_id=service,
        client_secret=sec,
        refresh_token=res['refresh_token'],
        token_expiry=datetime.now()+timedelta(seconds=res['expires_in']),
        token_uri=token_url,
        user_agent='testfarms v1.0') 
    if DEBUG:
        print 'Storing creds for later use'
        print 'return res: {0}'.format(res)
        print 'expires in: {0}'.format(res['expires_in'])
    if storage is None:
        fname = '{0}_{1}'.format(app_name,service)
        storage = Storage(fname)
    storage.put(credentials)
    flask.session['credentials'] = client.OAuth2Credentials.to_json(credentials)
    return flask.redirect(flask.url_for('query'))

def main():
    global redir, token_url, api_url, auth_url, service, sec
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
    WORK AROUND (part of #1 above) for obtaining Observant tokens (access and refresh): 
    see for details: https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
    '''
    token_url = 'https://{serv}:{sec}@test.obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)

    #start the flask server
    app.secret_key = str(uuid.uuid4())
    app.debug = False

    if len(sys.argv) > 1: #production/IP setting
        print 'using production environment'
        #alternative setup from a real server, once registered with Observant (including redirects)
	#register redirects (server IP, port, redir path/route (replace myfarm/oada here)) 
        #with openlink@observant.net
        SERVER='XXX.XXX.XXX.XXX'
        PORT='YYYY'
	REDIR_PATH='myfarm/oada'
        auth_url= 'https://obsrv.it/uaa/oauth/authorize'
        token_url = 'https://{serv}:{sec}@obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)
        api_url='https://obsrv.it/api/bookmarks' #works
    else:  #test/localhost
        #this is the only supported redirect for the Observant test account
        token_url = 'https://{serv}:{sec}@test.obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)
        print 'using test environment'
        SERVER='localhost'
        PORT='9977'
	REDIR_PATH='testfarms/oada'
    redir='http://{0}:{1}/{2}/'.format(SERVER,PORT,REDIR_PATH) 
    app.run(host=SERVER,port=PORT)

if __name__ == '__main__':
    main()

