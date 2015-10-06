import json, httplib2, traceback, requests, sys, argparse, csv
from datetime import datetime, timedelta
#Google APIs OAuth2 library: pip install --upgrade google-api-python-client
from oauth2client import client
from oauth2client.file import Storage
import logging

DEBUG = False
CLI_session = {}

#from https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
auth_url= 'https://test.obsrv.it/uaa/oauth/authorize'
token_url = 'https://test.obsrv.it/uaa/oauth/token'
api_url='https://test.obsrv.it/api/bookmarks' #works
api_url='https://test.obsrv.it/api/resources/davis/app-63bcecd2-719e-41b7-a198-9fbeee10f0c8/data' #works
#watermark test system
api_url='https://test.obsrv.it/api/resources/testfarms/sm_test_-_watermark/data' #works
service='XXX' 
sec='YYY' #contact jonathan.harvey@observant.net for this, place in creds.json (not in repo!)

obs_scope='sensor-data'
app_name = 'ObsServ'
#this is set in intialize_storage which must be run before all else, app entry is /
storage = None
#this is set in main and must map to app.run in main
redir = None

#You will also need a login and password for the test account 
#Contact jonathan.harvey@observant.net for these

################ initialize_storage ##################
def process_data(prefix,data):

    for reading in  data["readings"]:
        rid = reading["id"]
        fname = '{0}_{1}.csv'.format(prefix,rid)
        f = open(fname,'at')
        csvf = csv.writer(f)
        csvf.writerow(['reading_id','ts','val'])
        for entry in reading["entries"]:
            #timestamp format: 2015-09-26T22:00:00Z
            ts = entry["timestamp"]
	    dt = datetime.strptime(ts,'%Y-%m-%dT%H:%M:%SZ')
	    ts = dt.strftime('%Y-%m-%d %H:%M:%S')
            val = entry["value"]
            if val is None:
	        val = -1
            csvf.writerow([rid,ts,val])
        f.close()
        

################ initialize_storage ##################
def initialize_storage():
  '''
  Utility to grab the credentials from storage if any
  -- from https://developers.google.com/api-client-library/python/guide/aaa_oauth
  '''
  global storage
  fname = '{0}_{1}'.format(app_name,service)
  storage = Storage(fname)
  if DEBUG:
      print 'init_storage, storage fname: {0}'.format(fname)
  credentials = storage.get()
  if credentials is not None:
      CLI_session['credentials'] = client.OAuth2Credentials.to_json(credentials)
      if DEBUG:
          creds = json.loads(CLI_session['credentials'])
          print 'init_storage, got creds from storage: {0}'.format(creds)
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
    creds = json.loads(CLI_session['credentials']) 
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
            Protocol restart (oauth2setup) requires the user/customer to reauthorize our
            use of their account '''
        oauth2setup()
        return

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
    CLI_session['credentials'] = client.OAuth2Credentials.to_json(credentials)
    if DEBUG:
        print 'Stored creds at={0}'.format(res['access_token'])
    return 


################ query route ##################
def query(noauth=True):
    
    '''
    This function is invoked to access the Observant OpenLink API.
    It currently queries the url at api_url
    For more information on the API see: 
    https://github.com/ObservantPtyLtd/oada-client/blob/master/API.md
    '''
    if 'credentials' not in CLI_session:
        #check first to see if we have valid credentials stored away from a previous run
        if not initialize_storage():
            if noauth:
                print 'Error -- No prior creds to use, run without -n option'
                sys.exit(1)
            oauth2setup()
    creds = json.loads(CLI_session['credentials']) #json
    
    header = {'Authorization': 'Bearer {0}'.format(creds['access_token'])}
    r = None
    try:
        r = requests.get(api_url, headers=header)
    except requests.exceptions.RequestException as e:  
        print 'API Access failed: {0}'.format(e)
        output = {'name':'api_access_failed'}
        return output

    if r is not None:
	#This is where we insert the code for storing the data that comes back from the request
        if r.status_code == 401:  #unauthorized - check if refresh is needed, else regenerate from code
            refresh_creds()
            creds = json.loads(CLI_session['credentials']) #json
            header = {'Authorization': 'Bearer {0}'.format(creds['access_token'])}
            r = None
            try:
                r = requests.get(api_url, headers=header)
            except requests.exceptions.RequestException as e:  
                print 'API Access post refresh failed: {0}'.format(e)
                output = {'name':'api_access_post_refresh_failed'}
                return output

        if r is not None:
	    output = r.json()
        else: 
            output = {'name':'api_access_failed2'}
    else: 
        output = {'name':'api_access_failed3'}

    return output


################ oauth2 flow ##################
def oauth2setup():
    '''
    This method uses the Google oauth2setup library to perform the OAuth2 handshake.
    Because Observant uses a non-standard approach to code-token exchange, step2_exchange
    cannot be used directly.  Details below.
    '''
    global storage

    print 'Performing oauth2 web server flow'
    try:
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
        sys.exit(1)

    auth_uri = flow.step1_get_authorize_url()
    print 'Cut/Paste this URI into the URL box in\na browser window and press enter:\n\n{0}\n'.format(auth_uri)
    print 'You will be redirected to a URL and a page that says "Connection Refused"'
    auth_code = raw_input('Type in the code that appears after "code="\nin the URL box in your browser window, and press enter: ')

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
    print 'Storing creds for later use'
    if DEBUG:
        print 'return res: {0}'.format(res)
        print 'expires in: {0}'.format(res['expires_in'])
    if storage is None:
        fname = '{0}_{1}'.format(app_name,service)
        storage = Storage(fname)
    storage.put(credentials)
    CLI_session['credentials'] = client.OAuth2Credentials.to_json(credentials)
    return

def main():
    global redir, token_url, api_url, auth_url, service, sec
    logging.basicConfig()
    parser = argparse.ArgumentParser(description='Get and store Observant oauth2 creds. This program appends to all obs_*.csv files, so delete these before running.')
    parser.add_argument('--runquery','-r',action='store_true', default=False, help='Run a query?')
    parser.add_argument('--noauth','-n',action='store_true', default=False, help='Query using stored credentials only (for scripting purposes)')
    parser.add_argument('--prod','-p',action='store_true', default=False, help='Use production (Test is default)')
    args = parser.parse_args()
    #python ObsServ_CLI.py    //get creds if needed and store them for later
    #python ObsServ_CLI.py -r    //gets cred if needed and store them for later, and perform query
    #python ObsServ_CLI.py -r -n    //gets cred from storage and perform query
    #python ObsServ_CLI.py -p    //use production SERVER:PORT, get creds and store them 

    if args.prod: #production/IP setting
	creds_file = 'creds-prod.json'
    else:
	creds_file = 'creds.json'
    #read in the credentials (service and secret) from simple json file
    try: 
        with open(creds_file) as f:    
            data = json.load(f)
            service = data['service']
            sec = data['secret']
    except:
        print 'Error accessing creds.json file or with its file format.  It must contain the keys service and secret and be in the same directory as this program.'
        sys.exit(1)
        
    '''
    WORK AROUND (part of #1 above) for obtaining Observant tokens (access and refresh): 
    see for details: https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md
    '''

    if args.prod: #production/IP setting
        print 'using production environment'
        #alternative setup from a real server, once registered with Observant (including redirects)
        SERVER='128.111.84.220'
        PORT='8088'
        #SERVER='localhost' #not in redir list, but use 220
        auth_url= 'https://obsrv.it/uaa/oauth/authorize'
        token_url = 'https://{serv}:{sec}@obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)
        api_url='https://obsrv.it/api/bookmarks' #works
    else:  #test/localhost
        #this is the only supported redirect for the Observant test account
        token_url = 'https://{serv}:{sec}@test.obsrv.it/uaa/oauth/token'.format(serv=service,sec=sec)
        print 'using test environment'
        SERVER='localhost'
        PORT='9977'
    redir='http://{0}:{1}/smartfarm/oada/'.format(SERVER,PORT)  #must match SERVER/PORT

    if args.runquery:
        res = query(args.noauth)
        print api_url
        if 'bookmarks' in api_url:
            print res
        else:
            process_data('obs',res)
    elif not args.noauth:
        oauth2setup()
    else:
        print 'Running nothing (check your arguments)'

if __name__ == '__main__':
    main()

