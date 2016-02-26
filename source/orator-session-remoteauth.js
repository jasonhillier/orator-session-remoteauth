/**
* Orator/restify middleware to provide HTTP www-authenticate with orator-session
*
* @class OratorSessionRemoteAuth
* @constructor
*/
var OratorSessionRemoteAuth = function()
{
	function createNew(pFable)
	{
		// If a valid fable object isn't passed in, return a constructor
		if ((typeof(pFable) !== 'object') || (!pFable.hasOwnProperty('fable')))
			return {new: createNew};

		var _Settings = pFable.settings;
		var _Log = pFable.log;

		var libSession = require('orator-session').new(pFable);
		var libRestify = require('restify');
		var libRequest = require('request');

		/**
		* Wire up routes
		*
		* @method connectRoutes
		* @param {Object} pRestServer The Restify server object to add routes to
		*/
		var connectRoutes = function(pRestServer)
		{
			//connect orator-session handler into web server
			libSession.connectRoutes(pRestServer);

			//Routes here support different auth-types
			// depending on configuration (WWW-Auth for example)
			var tmpAuthTypes = _Settings.AuthTypes;
			if (!tmpAuthTypes) tmpAuthTypes = ['HTTP'];

			tmpAuthTypes.forEach(function(authType)
			{
				switch(authType)
				{
					case 'HTTP':
						pRestServer.use(httpAuthenticate);
						break;
					case 'POST':
						pRestServer.post('1.0/Authenticate', postAuthenticate);
						break;
					default:
						_Log.warn('Auth type ' + authType + ' not supported!');
						break;
				}
			});
		};

		/**
		 * Authenticate where credentials must verify against a remote Orator API server
		 * @method remoteAuthenticator
		 */
		var remoteAuthenticator = function(pCredentials, fCallback)
		{
			var tmpAuthResult = libSession.formatEmptyUserPacket(null);

			var tmpPostData = {
				url: _Settings.AuthenticationServerURL + 'Authenticate',
				json: true,
				body: {
					UserName: pCredentials.username,
					Password: pCredentials.password
				}
			};

			libRequest.post(tmpPostData,
				function (pError, pResponse, body)
				{
					//console.log(pResponse);

					if (pError ||
						(!body.UserID))
					{
						_Log.error('Invalid authentication response from remote Orator server!', {url: tmpPostData.url, user: pCredentials.username, error: pError});
						return fCallback('Invalid authentication response!');
					}

					if (body.UserID > 0) //current API
					{
						_Log.trace('Remote Orator auth successful', {Action:'Authenticate'});
						
						tmpAuthResult = body;

						// When the authenticator returns, the authResult normally inherits the active user's
						//  session, so we need to pocket this for later.
						tmpAuthResult.OverrideSessionID = tmpAuthResult.SessionID;
					}
					else
					{
						_Log.trace('Remote Orator auth denied');
					}

					return fCallback(body.Error, tmpAuthResult);
				});
		};

		/**
		 * Middleware Orator/restify route to handle HTTP Auth
		 * @method httpAuthenticate
		 */
		function httpAuthenticate(pRequest, pResponse, fNext)
		{
			if (libSession.checkIfLoggedIn(pRequest))
					return fNext();

			// new libRestify.NotAuthorizedError()
			if ('anonymous' === pRequest.username)
			{
				pResponse.statusCode = 401;
				pResponse.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
				pResponse.end('Access denied.  Need input.');

				return fNext;
			}
			else
			{
				pRequest.Credentials = (
				{
					username: pRequest.username,
					password: pRequest.authorization.basic.password
				});

				libSession.authenticateUser(pRequest, selectedAuthenticator, function(err, authResponse)
				{
					if (!authResponse ||
						!authResponse.LoggedIn)
					{
						_Log.trace('Remote auth failed');

						pResponse.statusCode = 401;
						pResponse.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
						pResponse.end('Access denied.  Need input.');
					}
					else
					{
						fNext();
					}
				});
			}
		};

		/**
		 * Set option to send redirect instead of auth response when using HTTP-POST authenticator
		 * @method setPostRedirectUrl
		 */
		var postRedirectUrl = null;
		var setPostRedirectUrl = function(pUrl)
		{
			postRedirectUrl = pUrl;
		};

		/**
		 * Middleware Orator/restify route to handle URL Auth
		 * @method postAuthenticate
		 */
		function postAuthenticate(pRequest, pResponse, fNext)
		{
			var tmpBody = pRequest.body;
			
			if (tmpBody['UserName'] &&
				tmpBody['Password'])
			{
				pRequest.Credentials = (
				{
					username: tmpBody.UserName,
					password: tmpBody.Password
				});

				libSession.authenticateUser(pRequest, selectedAuthenticator, function(err, authResponse)
				{
					if (!authResponse ||
						!authResponse.LoggedIn)
					{
						_Log.trace('Remote auth failed');

						pResponse.statusCode = 401;
						pResponse.end('Access denied.  Incorrect input.');
					}
					else
					{
						if (postRedirectUrl)
						{
							pResponse.header('Location', postRedirectUrl);
							pResponse.send(302);

							return fNext();
						}
						else
						{
							if (authResponse.OverrideSessionID)
							{
								authResponse.SessionID = authResponse.OverrideSessionID;
								//send a new cookie to client to sync it with our local session.
								// this makes it so we are sharing a session identifier locally and remotely.
								pRequest.SessionOverrideData = authResponse;
								libSession.createSession(pRequest, pResponse, function(err)
								{
									pResponse.send(authResponse);
									return fNext();
								});
							}
							else
							{
								pResponse.send(authResponse);
								return fNext();
							}
						}
					}
				});
			}
			else
			{
				pResponse.statusCode = 401;
				pResponse.end('Access denied. Need input.');

				return fNext;
			}
		};

		//TODO: property can be set to change the authenticator used by all login methods
		var selectedAuthenticator = remoteAuthenticator;

		var tmpOratorSession = (
		{
			connectRoutes: connectRoutes,
			setPostRedirectUrl: setPostRedirectUrl,
			checkIfLoggedIn: libSession.checkIfLoggedIn,
			checkSession: libSession.checkSession,
			new: createNew
		});

		return tmpOratorSession;
	}

	return createNew();
};


module.exports = new OratorSessionRemoteAuth();
