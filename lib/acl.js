/**
 * Checks if the user has the wanted roles
 *
 * @param request
 * @param reply
 */
exports.checkRoles = function(request, reply) {
  var user = request.auth.credentials;
  var requiredRole = request.pre.role;
  if (!exports.isGranted(user.role, requiredRole)) reply(Hapi.error.unauthorized('Unauthorized'));

  reply('Has grants');
  //reply({'bad': 'very'}).takeover().code(500); -- Take over example
};

exports.isGranted = function(userRole, requiredRole) {
  var userRoles = RoleHierarchy[userRole];
  return (userRoles.indexOf(requiredRole) > -1);
};

/**
 * Returns a function that returns the required role for an handler
 * @param ROLE
 * @returns {Function}
 */
exports.rolePrerequsites = function(ROLE) {
  return function(reqeust, reply) {
    reply(ROLE);
  };
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