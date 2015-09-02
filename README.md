# Observant-OpenLink

This program performs the OAuth2 handshake to obtain authorization from a user interested in sharing their Observant data with this app via the Observant Openlink API.  Our goal is to provide developers with a Python example similar to the <a href="https://github.com/ObservantPtyLtd/oada-client">Java example</a> provided by Observant.  The code is not production-quality or secure (we store the secret and access token in plain text files), but it provides a starting point for writing a service that interacts with the Observant API.

In order to use the program, you must contact Observant to get permission (and the client secret, test-user login, and test-user password) to access their test facility.  Place the client secret value in creds.json for the key 'secret'. Use the login and password when prompted to do so during the OAuth2 process.  Keeping everything else unchanged (including the required redirect URL), this program should work for you out of the box.  Improvements and suggestions are welcomed!

The program uses 
<ul><li>The <a href="https://github.com/ObservantPtyLtd/oada-client/blob/master/OAuth2-step-by-step.md">Observant Openlink OADA API</a>, 
</li><li> The <a href="from https://developers.google.com/identity/protocols/OAuth2WebServer">Google APIs OAuth2 library</a>.  Install via: pip install --upgrade google-api-python-client
</li><li> <a href="http://flask.pocoo.org/">Python Flask</a>
</li></ul>

Run the program via <tt>python ObsServ.py</tt>. And direct your browser to <a href="http://localhost:9977/">the server</a>.  More details can be found in the code concerning work arounds and issues with the Observant API and this oauth2 library.  

