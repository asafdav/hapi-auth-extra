// External modules
var Boom	= require('boom');
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

	if ((!user) || (!internals.isGranted(user.role, role, hierarchy))) {
		return Boom.forbidden('Unauthorized');
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

	var userRoles = null;

	// If we're using a hierarchy, get all the possible roles
	if(hierarchy) {
		var index = hierarchy.indexOf(userRole);	// Get the index of userRole in the hierarchy

		// If the user's role is not any of the possible roles
		if (index === -1) {
			return false;
		}

		userRoles = _.rest(hierarchy, index);	// Get all the possible roles in the hierarchy
	} else {
		userRoles = userRole;
	}

	/*console.log('userRole = '+userRole);
	console.log('requiredRole = '+requiredRole);
	console.log('userRoles = '+userRoles);*/

	// If the requiredRole is an array
	if(_.isArray(requiredRole)) {

		// If userRoles is an array, make sure that at least one of the user's roles is in the requiredRoles
		if(_.isArray(userRoles)) {
			return !_.isEmpty(_.intersection(userRoles, requiredRole));
		}
		// Else the userRoles is NOT an array. Make sure that the user's role is one of the required roles
		else {
			return (requiredRole.indexOf(userRoles) > -1);
		}
	}
	// Else the requiredRole is NOT an array. make sure that the user's role is in the requiredRoles
	else {

		// If the user has no roles
		if(!userRoles) {
			return false;
		}

		return (userRoles.indexOf(requiredRole) > -1);
	}
};

/**
 * Fetches the wanted acl entity using the provided
 *
 * @param query - function(id, cb) that returns the entity to the callback.
 * @param param - The "id" parameter that need to be provided for to the query
 * @param request - The originating request
 * @param cb - function(err, entity) that will be used to notify the caller about the result of the query
 */
exports.fetchEntity = (query, param, request, cb) => {

	return new Promise((resolve, reject) => {
    return query(param, request, function(err, entity) {

      if (err && err.isBoom) {
        return reject(err);
      } else if (err) {
        return reject(Boom.badRequest('Bad Request', err));
      }
      else if (!entity) {
        return reject(Boom.notFound());
      }
      else {
        resolve(entity);
      }
    });
  });
};


/**
 * Verifies that the user has permission to access the wanted entity.
 *
 * @param user - The authenticated user
 * @param role - The wanted role, undefined means any role
 * @param entity - Verify if the authenticated user has "role" grants and can access this entity
 * @param validator - The method that will be used to verify if the user has permissions, this method should be used on the provided entity.
 * @param options - additional options
 * @returns {promise|*|Promise}
 */
exports.validateEntityAcl = function(user, role, entity, validator, options) {

	return new Promise((resolve, reject) => {
    

    if (!entity) {
      reject(new Error('validateUserACL must run after fetchACLEntity'));
    } else if (!user) {
      reject(new Error('User is required, please make sure this method requires authentication'));
    } else {

      if (validator) {

        entity[validator](user, role, function(err, isValid) {

          if (err) {
            reject(new Error(err));
          } else if (!isValid) {	// Not granted
            reject(Boom.forbidden('Unauthorized'));
          } else {	// Valid
            resolve(isValid);
          }
        });
      } else {
        // Use the default validator
        var isValid = internals.defaultEntityAclValidator(user, role, entity, options);

        if (isValid) {
          resolve(isValid);
        } else {
          reject(Boom.forbidden('Unauthorized'));
        }
      }
    }

  });
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
