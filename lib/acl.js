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
    else if (!entity) return def.reject(Hapi.error.notFound());
    else def.resolve(entity);
  });

  return def.promise;
};

/**
 * Verifies that the user has permission to access the wanted entity.
 *
 * @param user - The authenticated user
 * @param role - The wanted role, undefined means any role
 * @param entity - Verify if the authenticated user has "role" grants and can access this entity
 * @param validator - The method that will be used to verify if the user has permissions, this method should be used on the provided entity.
 * @param options - additional options
 * @returns {promise|*|Q.promise}
 */
exports.validateEntityAcl = function(user, role, entity, validator, options) {
  var def = Q.defer();

  if (!entity) def.reject(new Error('validateUserACL must run after fetchACLEntity'));
  else if (!user) def.reject(new Error('User is required, please make sure this method requires authentication'));
  else {
    if (validator) {
      entity[validator](user, role, function(err, isValid) {
        if (err) def.reject(new Error(err));

        // Not granted
        else if (!isValid) def.reject(Hapi.error.unauthorized('Unauthorized'));

        // Valid
        else def.resolve(isValid);
      });
    } else {
      // Use the default validator
      var isValid = internals.defaultEntityAclValidator(user, role, entity, options);

      if (!isValid) def.reject(Hapi.error.unauthorized('Unauthorized'));
      else def.resolve(isValid);
    }
  }

  return def.promise;
};

/**
 * Default validator
 *
 * @param user
 * @param role
 * @param entity
 * @returns {*|string|boolean}
 */
internals.defaultEntityAclValidator = function(user, role, entity, options) {
  return (
    entity[options.entityUserField] &&
    user[options.userIdField] &&
    entity[options.entityUserField].toString() === user[options.userIdField].toString()
  );
};