/**
 * Created by asafdav on 17/05/14.
 */

// External modules
var Chai = require('chai');
var Hapi = require('hapi');

// Internal modules
var libpath = process.env['AUTH_EXTRA_COV'] ? '../lib-cov' : '../lib';
var Plugin = require(libpath + '/index');


// Declare internals
var internals = {};

// Test shortcuts
var expect = Chai.expect;

describe('Hapi-Auth-Extra', function() {

  describe('onPostAuth', function() {
    it('dummy', function(done) {
      var server = new Hapi.Server();
      server.route({ method: 'GET', path: '/', handler: function (request, reply) { reply("TEST"); } });

      server.inject('/', function(res) {
        expect(1).to.equal(1);
        done();
      });
    })
  });

});