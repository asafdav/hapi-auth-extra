/**
 * Created by asafdav on 17/05/14.
 */

// External modules
var Chai = require('chai');
var Hapi = require('hapi');

// Internal modules
var libpath = process.env['AUTH_EXTRA_COV'] ? '../lib-cov' : '../lib';
var Plugin = require(libpath + '/index');
var PluginObject = {
  name: 'hapiAuthExtra',
  version: '0.0.0',
  register: Plugin.register,
  path: libpath
};

// Declare internals
var internals = {};

// Test shortcuts
var expect = Chai.expect;

describe('hapiAuthExtra', function() {

  describe('Initialize', function() {

    it('makes sure that extra-auth can be enabled only for secured routes', function(done) {
      var server = new Hapi.Server(0);
      server.route({ method: 'GET', path: '/', config: {
        plugins: {'hapiAuthExtra': {role: 'USER'}},
        handler: function (request, reply) { reply("TEST");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.pack.start(function(err) {
          expect(err).to.not.be.undefined;
          expect(err).to.match(/extra-auth can be enabled only for secured route/);
          server.pack.stop(); // Make sure the server is stopped
          done();
        });
      });
    });

    it('Validates the extra-auth routes parameters', function(done) {
      var server = new Hapi.Server(0);
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});
      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {bla: 'USER'}},
        handler: function (request, reply) { reply("TEST");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        //expect(server.pack.start).to.throw(/extra-auth can be enabled only for secured route/);
        server.pack.start(function(err) {
          expect(err).to.not.be.undefined;
          expect(err).to.match(/the key bla is not allowed/);
          server.pack.stop(); // Make sure the server is stopped
        });
        done();
      });
    });

    it('ignores routes without extra auth instructions', function(done) {
      var server = new Hapi.Server();
      server.route({ method: 'GET', path: '/', handler: function (request, reply) { reply("TEST"); } });
      server.pack.register(PluginObject, {}, function(err) {
        server.inject('/', function(res) {
          expect(res.payload).to.equal("TEST");
          done();
        });
      });
    });
  });

  describe('ACL roles', function() {
    it('returns an error when a user with unsuited role tries to access a role protected route', function(done) {
      var server = new Hapi.Server();
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});

      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {role: 'ADMIN'}},
        handler: function (request, reply) { reply("TEST");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.inject({method: 'GET', url: '/', credentials: {role: 'USER'}}, function(res) {
          expect(res.statusCode).to.equal(401);
          expect(res.result.message).to.equal("Unauthorized");
          done();
        });
      });
    });

    it('Allows access to protected method for authorized users', function(done) {
      var server = new Hapi.Server();
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});

      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {role: 'ADMIN'}},
        handler: function (request, reply) { reply("Authorized");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
          expect(res.payload).to.equal('Authorized');
          done();
        });
      });
    });
  });

  describe('fetch ACL entities', function() {
    it('validates that the aclQuery parameter is a function', function(done) {
      var server = new Hapi.Server();
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});

      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {aclQuery: 'not function'}},
        handler: function (request, reply) { reply("Authorized");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
          expect(res.statusCode).to.equal(400)
          expect(res.result.message).to.match(/the value of aclQuery must be a Function/);
          done();
        });
      });
    });

    it('fetches the wanted entity using the query', function(done) {
      var server = new Hapi.Server();
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});

      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {aclQuery: function(id, cb) {
          cb(null, {id: '1', name: 'Asaf'});
        }}},
        handler: function (request, reply) { reply(request.plugins.hapiAuthExtra.entity);}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
          expect(res.statusCode).to.equal(200);
          expect(res.result.name).to.equal('Asaf');
          done();
        });
      });
    });

    it('handles not found entities', function(done) {
      var server = new Hapi.Server();
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});

      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {aclQuery: function(id, cb) {
          cb(null, null);
        }}},
        handler: function (request, reply) { reply("Oops");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
          expect(res.statusCode).to.equal(404);
          done();
        });
      });
    });

    it('handles query errors', function(done) {
      var server = new Hapi.Server();
      server.auth.scheme('custom', internals.authSchema);
      server.auth.strategy('default', 'custom', true, {});

      server.route({ method: 'GET', path: '/', config: {
        auth: true,
        plugins: {'hapiAuthExtra': {aclQuery: function(id, cb) {
          cb(new Error("Boomy"), null);
        }}},
        handler: function (request, reply) { reply("Oops");}
      }});
      server.pack.register(PluginObject, {}, function(err) {
        server.inject({method: 'GET', url: '/', credentials: {role: 'ADMIN'}}, function(res) {
          expect(res.statusCode).to.equal(500);
          done();
        });
      });
    });
  })

});

internals.authSchema = function() {
  var scheme = {
    authenticate: function (request, reply) {
      return reply(null, { username: "asafdav", role: 'USER'});
    },
    payload: function (request, next) {

      return next(request.auth.credentials.payload);
    },
    response: function (request, next) {

      return next();
    }
  };

return scheme;
}