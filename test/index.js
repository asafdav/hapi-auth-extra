// External modules
var expect = require('chai').expect;
var Hapi = require('hapi');

// Internal modules
var libpath = process.env['HAPI_AUTHORIZATION_COV'] ? '../lib-cov' : '../lib';
var Plugin = require(libpath + '/index');

// Declare internals
var internals = {};


describe('hapi-authorization', function() {

	var plugin = {
		name: 'hapiAuthorization',
		version: '0.0.0',
		register: Plugin.register,
		path: libpath
	};

	it('makes sure that hapi-authorization can be enabled only for secured routes', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.route({ method: 'GET', path: '/', config: {
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/hapi-authorization can be enabled only for secured route/);
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hapi-authorization for routes secured in the route config', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', false, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.be.undefined;
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hapi-authorization for routes secured globally with authentication', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', false, {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', config: {
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.be.undefined;
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hapi-authorization for routes secured globally with authentication and blacklisting routes to require authorization', function(done) {
		var server = new Hapi.Server(0);
		server.connection({
			routes: {
				plugins: {
					hapiAuthorization: { roles: ['USER'] }
				}
			}
		});
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', false, {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', config: {
			//plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.be.undefined;
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should error with global authentication not set and blacklisting routes to require authorization', function(done) {
		var server = new Hapi.Server(0);
		server.connection({
			routes: {
				plugins: {
					hapiAuthorization: { roles: ['USER'] }
				}
			}
		});
		//server.auth.scheme('custom', internals.authSchema);
		//server.auth.strategy('default', 'custom', false, {});
		//server.auth.default('default');
		server.route({ method: 'GET', path: '/', config: {
			//plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/hapi-authorization can be enabled only for secured route/);
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should not error with global authentication set, blacklisting routes to require authorization, and disabling authentication and authorization for a specific route', function(done) {

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: false
			}
		};

		var server = new Hapi.Server(0);
		server.connection({
			routes: {
				plugins: {
					hapiAuthorization: { roles: ['USER'] }
				}
			}
		});

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', false, {});
		server.auth.default('default');

		server.route({ method: 'GET', path: '/', config: {
			auth: false,
			plugins: {'hapiAuthorization': false},
			handler: function (request, reply) { reply("TEST");}
		}});

		server.register(plugin, {}, function(err) {
				server.inject({method: 'GET', url: '/'}, function(res) {
					console.log('err = ');
					console.log(err);
					console.log('res = ');
					console.log(res);
					internals.asyncCheck(function() {
						expect(res.statusCode).to.equal(200);
					}, done);
				});
		});
	});

	it('should error with global auth set but auth false on route', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', false, {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', config: {
			auth: false,
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.not.be.undefined;
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('Validates the hapi-authorization routes parameters', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', true, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});
		server.register(plugin, {}, function(err) {
			server.start(function(err) {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/bla is not allowed/);
				server.stop(); // Make sure the server is stopped
				done();
			});
		});
	});

	it('ignores routes without hapi-authorization instructions', function(done) {
		var server = new Hapi.Server();
		server.connection();
		server.route({ method: 'GET', path: '/', handler: function (request, reply) { reply("TEST"); } });
		server.register(plugin, {}, function(err) {

			console.log('err = ');
			console.log(err);

			server.inject('/', function(res) {
				//console.log(res);

				expect(res.payload).to.equal("TEST");
				done();
			});
		});
	});

	it('Validates the hapi-authorization plugin options do not contain random options', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', true, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				foo: 'TEST',
				roles: ['EMPLOYEE', 'OWNER', 'MANAGER'],
				hierarchy: true,
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		server.register(plugin, {}, function(err) {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: foo is not allowed');
			done();
		});
	});

	it('Validates the hapi-authorization plugin option "roles" must be an array', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', true, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: 'TEST',
				hierarchy: true,
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		server.register(plugin, {}, function(err) {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: roles must be an array roles must be a boolean');
			done();
		});
	});

	it('Validates the hapi-authorization plugin option "roleHierarchy" must be an array', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', true, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: true,
				roleHierarchy: 'Test'
			}
		};

		server.register(plugin, {}, function(err) {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: roleHierarchy must be an array');
			done();
		});
	});

	it('Validates the hapi-authorization plugin option "hierarchy" must be a boolean', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', true, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: 'TEST',
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		server.register(plugin, {}, function(err) {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: hierarchy must be a boolean');
			done();
		});
	});

	it('Validates the hapi-authorization plugin options are optional', function(done) {
		var server = new Hapi.Server(0);
		server.connection();
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', true, {});
		server.route({ method: 'GET', path: '/', config: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: function (request, reply) { reply("TEST");}
		}});

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath
		};

		server.register(plugin, {}, function(err) {
			expect(err).to.be.undefined;
			done();
		});
	});

	describe('Initialize with no options', function() {

		describe('ACL roles', function() {

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

			// TODO
			it.skip('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('returns an error when a user with a role that is not a valid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Allows access to protected method for a single role', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a single role is not one of the allowed roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(customPluginObject, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', function() {

			it('validates that the aclQuery parameter is a function', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/aclQuery must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, {id: '1', name: 'Asaf'});
					}}},
					handler: function (request, reply) { reply(request.plugins.hapiAuthorization.entity);}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(new Error("Boomy"), null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', function() {

			it('requires aclQuery when validateEntityAcl is true', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/aclQuery is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, null);
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, false)}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(new Error('Boom'))}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, true)}});
						}
					}},
					handler: function (request, reply) {
						reply(request.plugins.hapiAuthorization.entity);
					}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});
		});

		describe('default acl validator', function() {

			it('returns error when the entity has no user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: function(id, cb) {
							cb(null, {creator: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles', function() {

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE']
				//hierarchy: true,
				//roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', function() {

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', function() {

			it('validates that the aclQuery parameter is a function', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/aclQuery must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, {id: '1', name: 'Asaf'});
					}}},
					handler: function (request, reply) { reply(request.plugins.hapiAuthorization.entity);}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(new Error("Boomy"), null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', function() {

			it('requires aclQuery when validateEntityAcl is true', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/aclQuery is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, null);
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, false)}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(new Error('Boom'))}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, true)}});
						}
					}},
					handler: function (request, reply) {
						reply(request.plugins.hapiAuthorization.entity);
					}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});
		});

		describe('default acl validator', function() {

			it('returns error when the entity has no user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: function(id, cb) {
							cb(null, {creator: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles and hierarchy', function() {

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: true
				//roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', function() {

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Restricts access to protected route for multiple authorized roles that are not defined as plugin roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
							//expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', function() {

			it('validates that the aclQuery parameter is a function', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/aclQuery must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, {id: '1', name: 'Asaf'});
					}}},
					handler: function (request, reply) { reply(request.plugins.hapiAuthorization.entity);}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(new Error("Boomy"), null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});

		});

		describe('validateEntityAcl', function() {

			it('requires aclQuery when validateEntityAcl is true', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/aclQuery is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, null);
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, false)}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(new Error('Boom'))}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, true)}});
						}
					}},
					handler: function (request, reply) {
						reply(request.plugins.hapiAuthorization.entity);
					}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', function() {

			it('returns error when the entity has no user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: function(id, cb) {
							cb(null, {creator: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles and roleHierarchy', function() {

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				//hierarchy: true
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', function() {

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', function() {

			it('validates that the aclQuery parameter is a function', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/aclQuery must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, {id: '1', name: 'Asaf'});
					}}},
					handler: function (request, reply) { reply(request.plugins.hapiAuthorization.entity);}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(new Error("Boomy"), null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', function() {

			it('requires aclQuery when validateEntityAcl is true', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/aclQuery is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, null);
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, false)}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(new Error('Boom'))}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, true)}});
						}
					}},
					handler: function (request, reply) {
						reply(request.plugins.hapiAuthorization.entity);
					}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', function() {

			it('returns error when the entity has no user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: function(id, cb) {
							cb(null, {creator: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles, hierarchy, and roleHierarchy', function() {

		var plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: true,
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', function() {

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Restricts access to protected route for multiple authorized roles that are not defined as plugin roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							//expect(res.payload).to.equal('Authorized');
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: function (request, reply) { reply("TEST");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: function (request, reply) { reply("Authorized");}
				}});

				var plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					register: Plugin.register,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}, function(res) {
						internals.asyncCheck(function() {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: roles must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: role conflict with forbidden peer roles');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', function() {

			it('validates that the aclQuery parameter is a function', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/aclQuery must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, {id: '1', name: 'Asaf'});
					}}},
					handler: function (request, reply) { reply(request.plugins.hapiAuthorization.entity);}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(null, null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: function(id, cb) {
						cb(new Error("Boomy"), null);
					}}},
					handler: function (request, reply) { reply("Oops");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', function() {

			it('requires aclQuery when validateEntityAcl is true', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/aclQuery is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, null);
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, false)}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(new Error('Boom'))}});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello', isGranted: function(user, role, cb) {cb(null, true)}});
						}
					}},
					handler: function (request, reply) {
						reply(request.plugins.hapiAuthorization.entity);
					}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', function() {

			it('returns error when the entity has no user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {id: id, name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: function(id, cb) {
							cb(null, {_user: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', function(done) {
				var server = new Hapi.Server();
				server.connection();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', true, {});

				server.route({ method: 'GET', path: '/', config: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: function(id, cb) {
							cb(null, {creator: '1', name: 'Hello'});
						}
					}},
					handler: function (request, reply) { reply("Authorized");}
				}});
				server.register(plugin, {}, function(err) {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}, function(res) {
						internals.asyncCheck(function() {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});
});

internals.authSchema = function() {

	var scheme = {
		authenticate: function (request, reply) {
			return reply({ username: "asafdav", role: 'USER'});
		},
		payload: function (request, reply) {
			return reply(request.auth.credentials.payload);
		},
		response: function (request, reply) {
			return reply();
		}
	};

	return scheme;
};

internals.asyncCheck = function(f, done) {
	try {
		f();
		done();
	} catch(e) {
		done(e);
	}
}