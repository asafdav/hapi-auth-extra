/**
 * Created by asafdav on 3/11/14.
 */
var Hoek = require('hoek')

var Hapi = require('hapi');
var RoleHierarchy = require('./../model/document/user').RoleHierarchy;
var UserCollection = require('../model/collection/user');


/**
 * Implement the passport strategy
 * @param username
 * @param password
 * @param done
 */
exports.passportLocalStrategy = function(username, password, done) {
  UserCollection.login({email: username, password: password}, function(err, user) {
    if (err) return done(null, false, { 'message': 'An error occurred' });
    if (!user) return done(null, false, {'message': 'Invalid credentials'});

    return done(null, user);
  });
};

/**
 * Implements bearer authenticator
 * @param reply
 * @returns {Function}
 */
exports.bearerAuthenticator = function(reply) {
  return function(err, user, info) {
    if (err) return reply(Hapi.error.unauthorized(err));
    if (!user) return reply(Hapi.error.unauthorized('No user was found for this token'));
    return reply(null, { credentials: user });
  }
};

/**
 * Implements facebook authenticator
 * @param accessToken
 * @param refreshToken
 * @param profile
 * @param done
 * @returns {*}
 */
exports.facebookAuthenticator = function(accessToken, refreshToken, profile, done) {
  return done(null, false, {message: 'TBD'});
};

/**
 *  Find the user by token.  If there is no user with the given token, set
 *  the user to `false` to indicate failure.  Otherwise, return the
 *  authenticated `user`.  Note that in a production-ready application, one
 *  would want to validate the token for authenticity.
 *
 * @param token
 * @param done
 * @constructor
 */
exports.BearerStrategy = function(token, done) {
  UserCollection.findUserByToken(token, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }

    return done(null, user);
  });
};