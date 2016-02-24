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
	"TestUsername": "testuser",
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
						_OratorSessionHttpAuth.setPostRedirectUrl('http://somehwhere');

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
								.auth(_Orator.settings.TestUsername, _Orator.settings.TestPassword)
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
							Username: _Orator.settings.TestUsername,
							Password: _Orator.settings.TestPassword
						};
						libSuperTest
								.post('/1.0/Authenticate')
								.send(postBody)
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
					'Send auth by HTTP-POST FORM request, should be authorized',
					function(fDone)
					{
						libSuperTest
								.post('/1.0/Authenticate')
								.send('Username='+_Orator.settings.TestUsername+'&Password='+_Orator.settings.TestPassword)
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
			}
		);
	}
);
