/**
 * Created by asafdav on 21/05/14.
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

describe('AuthTokenSchema', function() {
  describe('initialize', function() {
    it('validated the presence of tokenValidator', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {tokenAuth: true}, function (err) {
        expect(err).to.be.defined;
        expect(err).to.match(/tokenValidator is required/);
        done();
      });
    });

    it('auth-token strategy is not available when tokenAuth is false', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {tokenAuth: false}, function (err) {
        expect(function() {server.auth.strategy('default', 'auth-token');}).to.throw(/unknown scheme: auth-token/);
        done();
      });
    });

    it('auth-token strategy is available when tokenAuth is enabled', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {tokenAuth: {tokenValidator: function() {}}}, function (err) {
        expect(function() {server.auth.strategy('default', 'auth-token');}).to.not.throw();
        done();
      });
    });
  });

  describe('#authenticate', function() {
    it ('returns error when a token is not found', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {tokenAuth: {tokenValidator: function(token, cb) {cb(null,null)}}}, function (err) {
        server.auth.strategy('default', 'auth-token');
        internals.routes(server);

        server.inject('/', function(res) {
          internals.asyncCheck(function() {
           expect(res.statusCode).equals(401);
           expect(res.result.message).equals("Can't authenticate the request");
          }, done)
        });
      });
    });

    it ('returns error when a token validator fails', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {
        tokenAuth: {
          tokenValidator: function(token, cb) {cb("BLA",null)},
          tokenSelector: function(request) {return "1"}
        }}, function (err) {
        server.auth.strategy('default', 'auth-token');
        internals.routes(server);

        server.inject('/', function(res) {
          internals.asyncCheck(function() {
            expect(res.statusCode).equals(500);
            expect(res.result.message).equals("An internal server error occurred");
          }, done)
        });
      });
    });

    it ('returns an error when a no user was found', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {
        tokenAuth: {
          tokenValidator: function(token, cb) {cb(null,null)},
          tokenSelector: function(request) {return "1"}
        }}, function (err) {
        server.auth.strategy('default', 'auth-token');
        internals.routes(server);

        server.inject('/', function(res) {
          internals.asyncCheck(function() {
            expect(res.statusCode).equals(401);
            expect(res.result.message).equals("Unknown user");
          }, done)
        });
      });
    });

    it ('returns the response for valid requests', function(done) {
      var server = new Hapi.Server(0);
      server.pack.register(PluginObject, {
        tokenAuth: {
          tokenValidator: function(token, cb) {cb(null,{name: 'Asaf'})},
          tokenSelector: function(request) {return "1"}
        }}, function (err) {
        server.auth.strategy('default', 'auth-token');
        internals.routes(server);

        server.inject('/', function(res) {
          internals.asyncCheck(function() {
            expect(res.statusCode).equals(200);
            expect(res.payload).equals("Authorized");
          }, done)
        });
      });
    });
  });
});

internals.routes = function(server) {
  server.route({ method: 'GET', path: '/', config: {
    auth: true,
    handler: function (request, reply) { reply("Authorized");}
  }});
};

internals.asyncCheck = function(f, done ) {
  try {
    f();
    done();
  } catch(e) {
    done(e);
  }
}