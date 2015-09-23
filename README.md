# Observant-OpenLink

This program performs the <a href="http://tools.ietf.org/html/rfc6749">OAuth2</a> handshake to obtain authorization from a user interested in sharing their Observant data with this app via the Observant Openlink API.  Our goal is to provide developers with a Python example similar to the <a href="https://github.com/ObservantPtyLtd/oada-client">Java example</a> provided by Observant.  The code is not production-quality or secure (we store the secret and access token in plain text files), but it provides a starting point for writing a service that interacts with the Observant API.

In order to use the program, you must contact Observant to get permission (and the client secret, test-user login, and test-user password) to access their test facility.  Place the client secret value in creds.json for the key 'secret'. Use the login and password when prompted to do so during the OAuth2 process.  Keeping everything else unchanged (including the required redirect URL), this program should work for you out of the box.  Improvements and suggestions are welcomed!

The program uses 
<ul><li>The <a href="https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md">Observant Openlink OADA API</a>, 
</li><li> The <a href="https://developers.google.com/identity/protocols/OAuth2WebServer">Google APIs OAuth2 library</a>.  Install via: pip install --upgrade google-api-python-client
</li><li> <a href="http://flask.pocoo.org/">Python Flask</a>
</li></ul>

Run the program via <tt>python ObsServ.py</tt>. And direct your browser to <a href="http://localhost:9977/">the server (http://localhost:9977/)</a>.  The initial handshake takes a few seconds to perform all of the redirects, so be patient.  More details can be found in the code concerning one work around required for Basic Auth credentials/access

To register a client with Observant you email Jon Havey and send him your preferred
<ul><li>client\_id, e.g. MyFarmClient</li>
<li>and redirect urls (http, https, static IP and localhost, port, and route, e.g.  http://XXX.XXX.XXX.XXX:9977/myfarm/oada, https://XXX.XXX.XXX.XXX:9977/myfarm/oada,  http://localhost:9977/myfarm/oada, https://localhost:9977/myfarm/oada</li>
<li></li>
He will send you the client secret in return.  Once you receive this you can test against the IP-based redirects by setting up your server at that IP and running the program via <tt>python ObsServ.py prod</tt>.
You should plug whichever redirect you are testing into redir=... in main in the production setting.

