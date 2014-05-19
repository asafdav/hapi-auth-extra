// External modules
var Hapi = require('hapi');
var Q = require('q');

// Internal modules
var RoleHierarchy = require('./roles').hierarchy;

// Declare of internals
var internals = {};


/**
 * Checks if the user has the wanted roles
 *
 * @param user
 * @param role
 * @returns {*}
 */
exports.checkRoles = function(user, role) {
  if (!internals.isGranted(user.role, role)) return Hapi.error.unauthorized('Unauthorized');
  return null;
};

/**
 * Checks if the provided user role is included is the wanted role or is included in the wanted role hierarchy
 * @param userRole
 * @param requiredRole
 * @returns {boolean}
 */
internals.isGranted = function(userRole, requiredRole) {
  var userRoles = RoleHierarchy[userRole];
  return (userRoles.indexOf(requiredRole) > -1);
};

/**
 * Fetches the wanted acl entity using the provided
 * @param query - function(id, cb) that returns the entity to the callback.
 * @param param - The "id" parameter that need to be provided for to the query
 * @param request - The originating request
 * @param cb - function(err, entity) that will be used to notify the caller about the result of the query
 */
exports.fetchEntity = function(query, param, cb) {
  var def = Q.defer();
  query(param, function(err, entity) {
    if (err) return def.reject(Hapi.error.internal('Bad request', err));
    if (!entity) return def.reject(Hapi.error.notFound());
    def.resolve(entity);
  });

  return def.promise;
};

/**
 * Verifies that the user has permission to access the wanted entity.
 * This pre function is depended on fetchACLEntity and must run after it as it needs the entity the verify
 * if the user has access to it.
 *
 * @param role - The wanted role, undefined means any role
 * @returns {Function}
 */
exports.validateACL = function(role) {
  return function(request, reply) {
    if (!request.pre.entity) throw Error('validateACL must run after fetchACLEntity');
    if (!request.auth.credentials) throw Error('User is required, please make sure this method requires authentication');
    var user = request.auth.credentials, entity = request.pre.entity;

    if(typeof entity.validateACL !== 'function')  throw Error(client.constructor.name + ' doesn\'t have validateACL method');
    entity.validateACL(user, role, function(err, isValid) {
      if (err) throw Error(err);

      // Not granted
      if (!isValid) reply(Hapi.error.unauthorized('Unauthorized', err));

      // Valid
      reply(isValid);
    });
  };
};