/**
 * Created by asafdav on 3/11/14.
 */
var Hoek = require('hoek');
var Boom = require('boom');

var internals = {};
var defaults = {
  tokenSelector: null,
  tokenValidator: null
};

exports.register = function(server, options) {
  server.auth.scheme('auth-token', internals.authSchema(options));
};


/**
 * Implements the authentication schema,
 *
 * @param options - A settings object that are needed for the authentication process, the allowed values are:
 * - tokenSelector - (optional) A synchronous function that extracts the token from the request. the default behaviour is to look for the Authorization header.
 * - tokenValidator - A function that validates if the token is valid and belongs to an active user, the function signature should be function(token, cb)
 * the cb signature is function(err,user)
 *
 * @param options
 * @returns {Function}
 */
internals.authSchema = function(options) {

  var settings = Hoek.applyToDefaults(defaults, options || {});
  Hoek.assert(!!settings.tokenValidator, 'tokenValidator is required');

  return function (server, funcOptions) {
    var scheme = {
      authenticate: function (request, reply) {
        // Find the token
        var token = (settings.tokenSelector ? settings.tokenSelector : internals.getAuthToken)(request);
        if (!token) return reply(Boom.unauthorized('Can\'t authenticate the request'));

        // Check if the token is valid
        settings.tokenValidator(token, function(err, user) {
          if (err) return reply(Boom.internal(err));
          if (!user) return reply(Boom.unauthorized("Unknown user"));

          // The user is valid, return it
          return reply.continue({credentials: user});
        });
      }
    };

    return scheme;
  };
};

/**
 * Default token selector implementation,
 * Fetches the token from the Authrization header, for example for "Authorization: Bearer 1" the function will return 1
 * If no authorization header is presented or it is in a bad format, a null will be returned.
 *
 * @param request
 * @returns {*}
 */
internals.getAuthToken = function(request) {
  if (request.headers && request.headers.authorization) {
    var parts = request.headers.authorization.split(' ');
    if (parts.length == 2) return parts[1];
  }

  return null;
};
