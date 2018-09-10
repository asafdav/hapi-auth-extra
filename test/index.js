// External modules
const expect = require('chai').expect;
const Hapi = require('hapi');
const Joi = require('joi');

// Internal modules
const libpath = process.env['HAPI_AUTHORIZATION_COV'] ? '../lib-cov' : '../lib';
const Plugin = require(libpath + '/index');

// Declare internals
const internals = {};

function NOOP(){}

describe('hapi-authorization', () => {

	const plugin = {
		name: 'hapiAuthorization',
		version: '0.0.0',
		register: Plugin.plugin.register,
		path: libpath
	};

	it('does not interfere with handlers throwing exceptions', async (done) => {
		const server = new Hapi.Server();
		server.route({ method: 'GET', path: '/', options: {
			handler: function (request, h) {return new Error("uncaught exception test");}
		}});
    await server.register(plugin, {});
    
    server.start().then(() => {
      server.inject({method: 'GET', url: '/'}).then((res) => {
        internals.asyncCheck(() => {
          expect(res.statusCode).to.equal(500);
          server.stop(NOOP);
        }, done);
      });
    });
	});

	it('makes sure that hapi-authorization can be enabled only for secured routes', (done) => {
		const server = new Hapi.Server();
		server.route({ method: 'GET', path: '/', options: {
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/hapi-authorization can be enabled only for secured route/);
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hapi-authorization for routes secured in the route config', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().then(() => {
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hapi-authorization for routes secured globally with authentication', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().then(() => {
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should allow hapi-authorization for routes secured globally with authentication and blacklisting routes to require authorization', (done) => {
		const server = new Hapi.Server({
			routes: {
				plugins: {
					hapiAuthorization: { roles: ['USER'] }
				}
			}
		});
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			//plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().then(() => {
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should error with global authentication not set and blacklisting routes to require authorization', (done) => {
		const server = new Hapi.Server({
			routes: {
				plugins: {
					hapiAuthorization: { roles: ['USER'] }
				}
			}
		});
		//server.auth.scheme('custom', internals.authSchema);
		//server.auth.strategy('default', 'custom', {});
		//server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			//plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/hapi-authorization can be enabled only for secured route/);
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('should not error with global authentication set, blacklisting routes to require authorization, and disabling authentication and authorization for a specific route', (done) => {

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: false
			}
		};

		const server = new Hapi.Server({
			routes: {
				plugins: {
					hapiAuthorization: { roles: ['USER'] }
				}
			}
		});

		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');

		server.route({ method: 'GET', path: '/', options: {
			auth: false,
			plugins: {'hapiAuthorization': false},
			handler: (request, h) => { return "TEST";}
		}});

		server.register(plugin, {}).then(() => {
				server.inject({method: 'GET', url: '/'}).then((res) => {
					internals.asyncCheck(() => {
						expect(res.statusCode).to.equal(200);
					}, done);
				});
		});
	});

	it('should error with global auth set but auth false on route', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.auth.default('default');
		server.route({ method: 'GET', path: '/', options: {
			auth: false,
			plugins: {'hapiAuthorization': {role: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('Validates the hapi-authorization routes parameters', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});
		server.register(plugin, {}).then(() => {
			server.start().catch((err) => {
				expect(err).to.not.be.undefined;
				expect(err).to.match(/"bla" is not allowed/);
				server.stop(NOOP); // Make sure the server is stopped
				done();
			});
		});
	});

	it('ignores routes without hapi-authorization instructions', (done) => {
		const server = new Hapi.Server();
		
		server.route({ method: 'GET', path: '/', handler: (request, h) => { return "TEST"; } });
		server.register(plugin, {}).then(() => {

			server.inject('/').then((res) => {

				expect(res.payload).to.equal("TEST");
				done();
			});
		});
	});

	it('Validates the hapi-authorization plugin options do not contain random options', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				foo: 'TEST',
				roles: ['EMPLOYEE', 'OWNER', 'MANAGER'],
				hierarchy: true,
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "foo" is not allowed');
			done();
		});
	});

	it('Validates the hapi-authorization plugin option "roles" must be an array', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: 'TEST',
				hierarchy: true,
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "roles" must be an array "roles" must be a boolean');
			done();
		});
	});

	it('Validates the hapi-authorization plugin option "roleHierarchy" must be an array', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: true,
				roleHierarchy: 'Test'
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "roleHierarchy" must be an array');
			done();
		});
	});

	it('Validates the hapi-authorization plugin option "hierarchy" must be a boolean', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: 'TEST',
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		server.register(plugin, {}).catch((err) => {
			expect(err).to.not.be.undefined;
			expect(err).to.be.instanceOf(Error);
			expect(err.message).to.equal('Invalid plugin options (Invalid settings) ValidationError: "hierarchy" must be a boolean');
			done();
		});
	});

	it('Validates the hapi-authorization plugin options are optional', (done) => {
		const server = new Hapi.Server();
		
		server.auth.scheme('custom', internals.authSchema);
		server.auth.strategy('default', 'custom', {});
		server.route({ method: 'GET', path: '/', options: {
			auth: 'default',
			plugins: {'hapiAuthorization': {bla: 'USER'}},
			handler: (request, h) => { return "TEST";}
		}});

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath
		};

		server.register(plugin, {}).then(() => {
			done();
		});
	});

	describe('Initialize with no options', () => {

		describe('ACL roles', () => {

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

			// TODO
			it.skip('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('returns an error when a user with a role that is not a valid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Allows access to protected method for a single role', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a single role is not one of the allowed roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(customPluginObject, {}, (err) => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hapiAuthorization.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hapiAuthorization.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});
		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: async (id, request) => {
							return {id: id, name: 'Hello'}
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
              return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
              return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
              return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
              return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

		describe('Joi validator with aclQuery', () => {

			it('returns an error when query parameter is missing', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					validate: {
						query: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'query',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid request query input');
						}, done);
					});
				});
			});

			it('validates query parameter', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					validate: {
						query: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'query',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/?name=John Doe', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('returns an error when payload parameter is missing', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'POST', path: '/', options: {
					validate: {
						payload: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'payload',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'POST', url: '/', payload: {}, credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid request payload input');
						}, done);
					});
				});
			});

			it('validates payload parameter', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'POST', path: '/', options: {
					validate: {
						payload: {
							name: Joi.string().required()
						}
					},
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQueryParam: 'name',
						paramSource: 'payload',
						aclQuery: (name, request) => {
							return {creator: '1', name: 'Hello' + name};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'POST', url: '/', payload: { name: "John Doe"}, credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles', () => {

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			register: Plugin.plugin.register,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE']
				//hierarchy: true,
				//roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', () => {

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hapiAuthorization.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
              return {id: id, name: 'Hello', isGranted: (user, role) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
              return {id: id, name: 'Hello', isGranted: (user, role) => { throw new Error('Boom'); }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
              return {id: id, name: 'Hello', isGranted: (user, role) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hapiAuthorization.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});
		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles and hierarchy', () => {

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: true
				//roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', () => {

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Restricts access to protected route for multiple authorized roles that are not defined as plugin roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hapiAuthorization.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});

		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hapiAuthorization.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles and roleHierarchy', () => {

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				//hierarchy: true
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', () => {

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			// TODO
			it.skip('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hapiAuthorization.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hapiAuthorization.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});

	describe('Initialize with roles, hierarchy, and roleHierarchy', () => {

		const plugin = {
			name: 'hapiAuthorization',
			version: '0.0.0',
			plugin: Plugin.plugin,
			path: libpath,
			options: {
				roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
				hierarchy: true,
				roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
			}
		};

		describe('ACL roles', () => {

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with an invalid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'ADMIN'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Restricts access to protected route for multiple authorized roles that are not defined as plugin roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
							expect(res.statusCode).to.equal(200);
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

			it('returns an error when a user with unsuited role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns an error when a user with a role that is not a valid role tries to access a role protected route', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'OWNER'}},
					handler: (request, h) => { return "TEST";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'KING'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Allows access to protected method for a single role', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Allows access to protected method for multiple authorized roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['EMPLOYEE', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.payload).to.equal('Authorized');
						}, done);
					});
				});
			});

			it('Returns an error when a single role is not one of the allowed roles', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: ['OWNER', 'MANAGER']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'EMPLOYEE'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'MANAGER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when a user\'s role is unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when any of a user\'s roles are unsuited due to hierarchy being disabled', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'EMPLOYEE'}},
					handler: (request, h) => { return "Authorized";}
				}});

				const plugin = {
					name: 'hapiAuthorization',
					version: '0.0.0',
					plugin: Plugin.plugin,
					path: libpath,
					options: {
						roles: ['OWNER', 'MANAGER', 'EMPLOYEE'],
						hierarchy: false,
						roleHierarchy: ['OWNER', 'MANAGER', 'EMPLOYEE']
					}
				};

				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'OWNER'}}).then((res) => {
						internals.asyncCheck(() => {

							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('Returns an error when specifying role (singular) with an array', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" must be a string');
						}, done);
					});
				});
			});

			it('Returns an error when specifying roles (plural) with a string', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {roles: 'USER'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "roles" must be an array');
						}, done);
					});
				});
			});

			it('Returns an error when specifying both role and roles as options', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {role: 'USER', roles: ['USER', 'ADMIN']}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.equal('Invalid route options (Invalid settings) ValidationError: "role" conflict with forbidden peer "roles"');
						}, done);
					});
				});
			});

		});

		describe('fetchEntity', () => {

			it('validates that the aclQuery parameter is a function', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: 'not function'}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400)
							expect(res.result.message).to.match(/"aclQuery" must be a Function/);
						}, done);
					});
				});
			});

			it('fetches the wanted entity using the query', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return {id: '1', name: 'Asaf'};
					}}},
					handler: (request, h) => { return request.plugins.hapiAuthorization.entity;}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Asaf');
						}, done);
					});
				});
			});

			it('handles not found entities', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						return null;
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('handles query errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {aclQuery: (id, request) => {
						throw new Error("Boomy");
					}}},
					handler: (request, h) => { return "Oops";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
						}, done);
					});
				});
			});
		});

		describe('validateEntityAcl', () => {

			it('requires aclQuery when validateEntityAcl is true', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {validateEntityAcl: true}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(400);
							expect(res.result.message).to.match(/"aclQuery" is required/);
						}, done);
					});
				});
			});

			it('returns an error when the entity was not found', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return null;
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(404);
						}, done);
					});
				});
			});

			it('declines requests from unauthorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return false; }};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
						}, done);
					});
				});
			});

			it('handles validator errors', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { throw new Error('Boom')}};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(500);
						}, done);
					});
				});
			});

			it('returns the response for authorized users', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						validateAclMethod: 'isGranted',
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello', isGranted: (user, role) => { return true; }};
						}
					}},
					handler: (request, h) => {
						return request.plugins.hapiAuthorization.entity;
					}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result.name).to.equal('Hello');
						}, done);
					});
				});
			});

		});

		describe('default acl validator', () => {

			it('returns error when the entity has no user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {id: id, name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns error when the entity doesn\'t belong to the authenticated user', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '2'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(403);
							expect(res.result.message).to.equal("Unauthorized");
						}, done);
					});
				});
			});

			it('returns the response for user with permissions', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom user id field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						userIdField: 'myId',
						aclQuery: (id, request) => {
							return {_user: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', myId: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

			it('handles custom entity user field', (done) => {
				const server = new Hapi.Server();
				
				server.auth.scheme('custom', internals.authSchema);
				server.auth.strategy('default', 'custom', {});

				server.route({ method: 'GET', path: '/', options: {
					auth: 'default',
					plugins: {'hapiAuthorization': {
						validateEntityAcl: true,
						entityUserField: 'creator',
						aclQuery: (id, request) => {
							return {creator: '1', name: 'Hello'};
						}
					}},
					handler: (request, h) => { return "Authorized";}
				}});
				server.register(plugin, {}).then(() => {
					server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN', _id: '1'}}).then((res) => {
						internals.asyncCheck(() => {
							expect(res.statusCode).to.equal(200);
							expect(res.result).to.equal("Authorized");
						}, done);
					});
				});
			});

		});

	});
});

internals.authSchema = () => {

	const scheme = {
		authenticate: (request, h) => {
			return { username: "asafdav", role: 'USER'};
		},
		payload: (request, h) => {
			return request.auth.credentials.payload;
		},
		response: (request, h) => {
			return {};
		}
	};

	return scheme;
};

internals.asyncCheck = (f, done) => {
	try {
		f();
		done();
	} catch(e) {
		done(e);
	}
}
