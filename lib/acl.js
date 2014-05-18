// External modules
var Hapi = require('hapi');

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
 * Uses the provided query to fetch the wanted entity.
 *
 * @param query - function(id, cb) that returns the entity to the callback.
 * @param param - The route parameter to use in order to fetch the entity (useually id)
 *
 * @returns {Function}
 */
exports.fetchACLEntity = function(query, param) {
  return function(request, reply) {
    var entityId = request.params[param];
    query(entityId, function(err, entity) {
      if (err) return reply(Hapi.error.internal('Bad request', err));
      if (!entity) return reply(Hapi.error.notFound());
      reply(entity);
    });
  };
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