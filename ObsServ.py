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
#this is the only support redirect for the Observant test account
redir='http://localhost:9977/testfarms/oada/'
obs_scope='sensor-data'
app_name = 'ObsServ'
storage = None

#You will also need a login and password for the test account 
#Contact jonathan.harvey@observant.net for these

################ initialize_storage ##################
def initialize_storage():
  '''
  Utility to grab the credentials from storage if any
  -- from https://developers.google.com/api-client-library/python/guide/aaa_oauth
  '''
  global storage
  fname = '{}_{}'.format(app_name,service)
  storage = Storage(fname)
  credentials = storage.get()
  print 'credentials: {}'.format(credentials)
  if credentials is not None:
      flask.session['credentials'] = client.OAuth2Credentials.to_json(credentials)
      return True
  return False
    

################ refresh_creds ##################
def refresh_creds():

    '''
    Utility to refresh OAuth2 access_token.
    Refresh is currently not supported by Observant OpenLink.
    '''
    global storage
    print 'Token has expired... refreshing'
    creds = json.loads(flask.session['credentials']) 
    payload = {'grant_type':creds['refresh_token'], 
        'client_id':creds['client_id'], 
        'redirect_uri':redir}
    r = requests.post(creds['token_uri'], params=payload)
    res = r.json()
    if 'error' in res:
        print 'refresh error: {}'.format(res['error'])
        return flask.redirect(flask.url_for('oauth2callback'))

    #create a new creds object and save it off
    credentials = client.OAuth2Credentials(access_token=res['access_token'],client_id=creds['client_id'],client_secret=creds['client_secret'],refresh_token=creds['refresh_token'],token_expiry=datetime.now()+timedelta(seconds=res['expires_in']),token_uri=creds['token_uri'],user_agent=creds['user_agent'])
    if storage is None:
        fname = '{}_{}'.format(app_name,service)
        storage = Storage(fname)
    storage.put(credentials)
    flask.session['credentials'] = client.OAuth2Credentials.to_json(credentials)
    return flask.redirect(flask.url_for('index'))


################ index route ##################
@app.route('/')
def index():

    '''
    This function is invoked to access the Observant OpenLink API.
    It currently queries the https://test.obsrv.it/api/bookmarks
    For more information on the API see: 
    https://github.com/ObservantPtyLtd/oada-client/blob/master/API.md

    If there are no credentials, it redirects to oauth2callback to get them.
    If there are credentials, but the access token has expired, it calls
    refresh_creds as a workaround for oauth2client refresh which does not work.
    Since refresh is currently not supported by Observant, this results in 
    a redirect to oauth2callback to get the credentials.  Given this lack of 
    support, users are required to authorize this app every 24 hours (token expiration).
    '''

    if 'credentials' not in flask.session:
        #check first to see if we have valid credentials stored away from a previous run
        if not initialize_storage():
            return flask.redirect(flask.url_for('oauth2callback'))


    ''' WORK AROUND ------------------------
        The following should but does not work.  
        It may be due to how the token_expiry is stored.
           credentials.access_token_expired is True even when the
           token has not yet expired.
        Instead we perform the refresh manually below.
    
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        http = httplib2.Http()
        credentials.refresh(http)
    ----------------------------------------'''

    creds = json.loads(flask.session['credentials']) #json
    exp = datetime.strptime(creds['token_expiry'], '%Y-%m-%dT%H:%M:%SZ')
    dtn = datetime.now()
    mins = 24*60
    if exp < dtn:
        print 'token has expired'   
        #Manual refresh of the token
        refresh_creds() #refresh is not yet supported by Observant, this will reroute to auth2callback ultimately
    else:
        mins = (exp-dtn).total_seconds() / 60
        print 'token will expire in {} minutes'.format(mins)
  
    #Access the API, dump json result to the console
    header = {'Authorization': 'Bearer {}'.format(creds['access_token'])}
    r = None
    try:
        r = requests.get(api_url, headers=header)
    except requests.exceptions.RequestException as e:  
        print e
        return 'Observant API access failed: {}'.format(e)
    if r is not None:
        print r.text
    return 'Observant API access succeeded: TTL={} mins'.format(mins)


################ oauth2 callback route ##################
@app.route('/testfarms/oada/')  #required by Observant testing environment
def oauth2callback():
    '''
    This method uses the Google oauth2callback library to perform the OAuth2 handshake.
    Because Observant sues a non-standard approach to code-token exchange, step2_exchange
    cannot be used directly.  Thus, we implement a work around for this step.
    '''
    global storage

    print auth_url, token_url
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

    ''' WORK AROUND ------------------------
        The following returns unauthorized as if the appropriate headers 
            or full url (username,pwd) is not being passed correctly.
	    Likely due to non-standard OAuth2 implementation on Observant side
    try:
        credentials = flow.step2_exchange(auth_code)
    except client.FlowExchangeError, e:
        print 'Authentication failed: {}'.format(e)
    ----------------------------------------'''

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
        fname = '{}_{}'.format(app_name,service)
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
        

    #work around for obtaining Observant tokens: 
    #https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
    token_url = 'https://{serv}:{sec}@test.obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)

    #start the flask server
    app.secret_key = str(uuid.uuid4())
    app.debug = False
    #this is the only IP/port supported by the Observanttest account
    app.run(host='localhost',port=9977)
