// External modules
var Boom	= require('boom');
var Hoek	= require('hoek');
var Q			= require('q');

// Internal modules
var Roles					= require('./roles');
var Schema				= require('./schema');
var RoleHierarchy	= Roles.hierarchy;
var ACL						= require('./acl');

var pluginName = 'hapiAuthorization';
var internals = {
  defaults: {
    roles: Roles.roles,
		hierarchy: false,
		roleHierarchy: RoleHierarchy
  }
};

/**
 * Registers the plugin
 *
 * @param plugin
 * @param options
 * @param next
 */
exports.register = function (plugin, options, next) {

  try {
		// Validate the options passed into the plugin
		Schema.assert('plugin', options, 'Invalid settings');

    var settings = Hoek.applyToDefaults(internals.defaults, options || {});

    plugin.bind({
      config: settings
    });

		// Validate the plugin options on the routes
    plugin.after(internals.validateRoutes);
		//plugin.ext('onPreAuth', internals.onPreAuth);
		plugin.ext('onPostAuth', internals.onPostAuth);

    next();
  } catch (e) {
    next(e);
  }
};

/**
 * Gets the name and version from package.json
 */
exports.register.attributes = {
	pkg: require('../package.json')
}


/**
 * Runs on server start and validates that every route that has hapi-authorization params is valid
 *
 * @param plugin
 * @param next
 */
internals.validateRoutes = function(plugin, next) {

  try {

		// Loop through each server in the pack
    plugin.servers.forEach(function(server) {

			var routes = (server.routingTable) ? server.routingTable() : server.table();

			// Loop through each route
			routes.forEach(function(route) {
        var hapiAuthorizationParams = route.settings.plugins[pluginName] ? route.settings.plugins[pluginName] : false;

				// If there are hapi-authorization params, validate em
        if (hapiAuthorizationParams) {

          Hoek.assert(route.settings.auth && route.settings.auth !== null, 'hapi-authorization can be enabled only for secured route');

          Schema.assert('route', hapiAuthorizationParams, 'Invalid settings');
        }
      });
    });

    next();
  }
  catch (err) {
    next(err);
  }
};

/*internals.onPreAuth = function(request, next) {

	try {
		next();
	} catch (err) {
		next(next(Hapi.error.badRequest(err.message)));
	}
}*/

/**
 * Checks if hapi-authorization is active for the current route and execute the necessary steps accordingly.
 *
 * @param request
 * @param next
 */
internals.onPostAuth = function(request, next) {

  try {

    // Check if the current route is hapi-authorization enabled
    var params = internals.getRouteParams(request);

		// if hapi-authorization is enabled, get the user
    if (params) {

      var user = request.auth.credentials;

      if (!request.plugins[pluginName]) {
				request.plugins[pluginName] = {};
			}

			var roleHierarchy = null;

			// If we're not using hierarchy
			if(this.config.hierarchy === true) {
				// this.config comes from plugin.bind
				roleHierarchy = this.config.roleHierarchy;
			} else {
				roleHierarchy = false;
			}

      Q
        // Checks roles
        .fcall(function () {
					if (params.role || params.roles) {

            var err = ACL.checkRoles(user, params.role || params.roles, roleHierarchy);
            if (err) {
							throw err;
						}
          }
          return true;
        })
        // Fetches acl entities
        .then(function () {
          if (params.aclQuery) {
            var parameter = request[params.paramSource][params.aclQueryParam];
            return ACL.fetchEntity(params.aclQuery, parameter, request);
          }
          return null;
        })
        // Store the entity
        .then(function(entity) {
          if (entity) {
            request.plugins[pluginName].entity = entity;
            return entity;
          }
        })
        // Validate the ACL settings
        .then(function(entity) {
          if (params.validateEntityAcl) {
            if (!entity) {
							throw new Error('Entity is required');
						}

            return ACL.validateEntityAcl(user, params.role, entity, params['validateAclMethod'], params);
          }
          return null;
        })
        .then(function () {
          next();
        })
        // Handles errors
        .catch(function (err) {
          next(err);
        });

    } else {
      next();
    }
  }
  catch (err) {
    next(Boom.badRequest(err.message));
  }};

/**
 * Returns the plugin params for the current request
 *
 * @param request
 * @returns {*}
 */
internals.getRouteParams = function(request) {

  if (request.route.plugins[pluginName]) {
    var params = request.route.plugins[pluginName];
    return Schema.assert('route', params, 'Invalid settings');
  } else {
    return null;
  }
};