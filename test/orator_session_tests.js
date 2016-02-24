/**
* Unit tests for OratorSessionRemoteAuth on Orator Server
*
* @license     MIT
*
* @author      Jason Hillier <jason.hillier@paviasystems.com>
*/

var Chai = require("chai");
var Expect = Chai.expect;
var Assert = Chai.assert;

var _MockSettings = (
{
	Product: 'MockOratorAlternate',
	ProductVersion: '0.0.0',
	AuthenticationServerURL: "http://127.0.0.1/1.0/",
	AuthTypes: ['HTTP','POST'],
	APIServerPort: 8080,
	"SessionTimeout":60,
	"MemcachedURL":"127.0.0.1:11211",
	"TestUserName": "testuser",
	"TestPassword": "testpassword",
	"ConfigFile":__dirname+"/../Orator-Config.json"
});

var libSuperTest = require('supertest').agent('http://localhost:' + _MockSettings.APIServerPort + '/');


suite
(
	'PaviaSessionHttpAuth',
	function()
	{
		var _OratorSessionHttpAuth;

		setup
		(
			function()
			{
				var fable = require('fable').new(_MockSettings);
				_OratorSessionHttpAuth = require('../source/orator-session-remoteauth').new(fable);
			}
		);

		suite
		(
			'Object Sanity',
			function()
			{
				test
				(
					'initialize should build a happy little object',
					function()
					{
						Expect(_OratorSessionHttpAuth)
							.to.be.an('object', 'OratorSessionHttpAuth should initialize as an object directly from the require statement.');
					}
				);
			}
		);

		suite
		(
			'Orator Session with Orator web Server',
			function()
			{
				var _Orator;
				var _OratorSessionHttpAuth;

				test
				(
					'Initialize Orator',
					function()
					{
						_Orator = require('orator').new(_MockSettings);
					}
				);
				test
				(
					'Start Orator web Server',
					function()
					{
						_OratorSessionHttpAuth = require('../source/orator-session-remoteauth').new(_Orator);
						_OratorSessionHttpAuth.connectRoutes(_Orator.webServer);

						//setup a route to use for testing
						_Orator.webServer.get(
							'/TEST',
							function (pRequest, pResponse, fNext)
							{
								pResponse.send('TEST');
								fNext();
							}
						);

						_Orator.startWebServer();
					}
				);
				test
				(
					'Send test request, should be unauthorized',
					function(fDone)
					{
						libSuperTest
								.get('TEST')
								.end(
									function (pError, pResponse)
									{
										Expect(pResponse.statusCode)
											.to.equal(401);
										fDone();
									}
								);
					}
				);
				test
				(
					'Send bad login request, should be unauthorized',
					function(fDone)
					{
						libSuperTest
								.get('TEST')
								.auth('bad', 'wrong')
								.end(
									function (pError, pResponse)
									{
										Expect(pResponse.statusCode)
											.to.equal(401);
										fDone();
									}
								);
					}
				);
				test
				(
					'Send login request, should be authorized',
					function(fDone)
					{
						libSuperTest
								.get('TEST')
								.auth(_Orator.settings.TestUserName, _Orator.settings.TestPassword)
								.end(
									function (pError, pResponse)
									{
										Expect(pResponse.statusCode)
											.to.equal(200);
										fDone();
									}
								);
					}
				);
				test
				(
					'Send auth by HTTP-POST request, should be authorized',
					function(fDone)
					{
						var postBody =
						{
							UserName: _Orator.settings.TestUserName,
							Password: _Orator.settings.TestPassword
						};
						libSuperTest
								.post('/1.0/Authenticate')
								.send(postBody)
								.end(
									function (pError, pResponse)
									{
										var tmpAuthToken = pResponse.body;

										Expect(tmpAuthToken)
											.to.have.property('UserRole');
										Expect(tmpAuthToken.LoggedIn)
											.to.equal(true);
										fDone();
									}
								);
					}
				);
				test
				(
					'Send auth by HTTP-POST FORM request, should be authorized',
					function(fDone)
					{
						//have post-authenticator redirect instead of sending back auth token
						_OratorSessionHttpAuth.setPostRedirectUrl('http://somehwhere');

						libSuperTest
								.post('/1.0/Authenticate')
								.send('UserName='+_Orator.settings.TestUserName+'&Password='+_Orator.settings.TestPassword)
								.end(
									function (pError, pResponse)
									{
										Expect(pResponse.statusCode)
											.to.equal(302);
										fDone();
									}
								);
					}
				);
				test
				(
					'Send test request, should still be authorized',
					function(fDone)
					{
						libSuperTest
								.get('TEST')
								.end(
									function (pError, pResponse)
									{
										Expect(pResponse.statusCode)
											.to.equal(200);
										fDone();
									}
								);
					}
				);
				test
				(
					'Run checkSession',
					function(fDone)
					{
						libSuperTest
								.get('1.0/CheckSession')
								.end(
									function (pError, pResponse)
									{
										var tmpAuthToken = pResponse.body;

										Expect(pResponse.statusCode)
											.to.equal(200);
										Expect(tmpAuthToken)
											.to.have.property('UserRole');
										Expect(tmpAuthToken.LoggedIn)
											.to.equal(true);
										fDone();
									}
								);
					}
				);
			}
		);
	}
);
