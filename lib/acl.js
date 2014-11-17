// External modules
var Hapi	= require('hapi');
var Q			= require('q');
var _			= require('underscore');

// Declare of internals
var internals = {};


/**
 * Checks if the user has the wanted roles
 *
 * @param user	- The user to check if they have a role
 * @param role	- The role to check if the user has
 * @returns {*}
 */
exports.checkRoles = function(user, role, hierarchy) {

	if (!internals.isGranted(user.role, role, hierarchy)) {
		return Hapi.error.unauthorized('Unauthorized');
	}

  return null;
};

/**
 * Checks if the provided user role is included is the required role or is included in the required role hierarchy
 *
 * @param userRole			- The role(s) that the user has
 * @param requiredRole	- The role(s) that is required
 * @returns {boolean}		- True/False whether the user has access
 */
internals.isGranted = function(userRole, requiredRole, hierarchy) {

	var index = hierarchy.indexOf(userRole);	// Get the index of userRole in the hierarchy

	// If the user's role is not any of the possible roles
	if(index === -1) {
		return false;
	}

	var userRoles = _.rest(hierarchy, index);	// Get all the possible roles in the hierarchy

	// If the requiredRole is an array, make sure that at least one of the user's roles is in the requiredRoles
	// Else if the requiredRole is NOT an array, make sure that the user's role is in the requiredRoles
	if(_.isArray(requiredRole)) {
		return !_.isEmpty(_.intersection(userRoles, requiredRole));
	} else {
		return (userRoles.indexOf(requiredRole) > -1);
	}
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

  if (!entity) {
		def.reject(new Error('validateUserACL must run after fetchACLEntity'));
	} else if (!user) {
		def.reject(new Error('User is required, please make sure this method requires authentication'));
	} else {

    if (validator) {

			entity[validator](user, role, function(err, isValid) {

				if (err) {
					def.reject(new Error(err));
				} else if (!isValid) {	// Not granted
					def.reject(Hapi.error.unauthorized('Unauthorized'));
				} else {	// Valid
					def.resolve(isValid);
				}
      });
    } else {
      // Use the default validator
      var isValid = internals.defaultEntityAclValidator(user, role, entity, options);

      if (isValid) {
				def.resolve(isValid);
			} else {
				def.reject(Hapi.error.unauthorized('Unauthorized'));
			}
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