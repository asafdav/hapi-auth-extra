// External modules
const Boom	= require('boom');
const Hoek	= require('hoek');

// Internal modules
const Roles					= require('./roles');
const Schema				= require('./schema');
const RoleHierarchy	= Roles.hierarchy;
const ACL						= require('./acl');

const pluginName = 'hapiAuthorization';
const internals = {
	defaults: {
		roles: Roles.roles,
		hierarchy: false,
		roleHierarchy: RoleHierarchy
	}
};

/**
 * Registers the plugin
 *
 * @param server
 * @param options
 */
const register = (server, options) => {

  // Validate the options passed into the plugin
  Schema.assert('plugin', options, 'Invalid settings');

  const settings = Hoek.applyToDefaults(internals.defaults, options || {});

  server.bind({
    config: settings
  });

  // Validate the server options on the routes
  if (server.after) { // Support for hapi < 11
    server.after(internals.validateRoutes);
  } else {
    server.ext('onPreStart', internals.validateRoutes);
  }
  server.ext('onPreHandler', internals.onPreHandler);

};

/**
 * Gets the name and version from package.json
 */
exports.plugin = {
  register,
  name: pluginName,
  version: require('../package.json').version,
  multiple: true,
  pkg: require('../package.json')
};


/**
 * Runs on server start and validates that every route that has hapi-authorization params is valid
 *
 * @param server
 */
internals.validateRoutes = (server) => {

	const routes = server.table();

	// Loop through each route
	routes.forEach((route) => {

		const hapiAuthorizationParams = route.settings.plugins[pluginName] ? route.settings.plugins[pluginName] : false;

		// If there are hapi-authorization params and are not disabled by using "false", validate em
		if (hapiAuthorizationParams !== false) {

			// If there is a default auth
			if (server.auth.settings.default) {

				// If there is also an auth on the route, make sure it's not false or null
				if (route.settings.auth !== undefined) {

					// Make sure that there is either a default auth being set, or that there is an auth specified on every route with hapiAuthorization plugin params
					Hoek.assert(route.settings.auth !== null && route.settings.auth !== false, 'hapi-authorization can be enabled only for secured route');
				}
			}
			// Else there is no default auth set, so validate each route's auth
			else {
				// Make sure that there is either a default auth being set, or that there is an auth specified on every route with hapiAuthorization plugin params
				Hoek.assert(route.settings.auth && route.settings.auth !== null && route.settings.auth !== false, 'hapi-authorization can be enabled only for secured route');
			}

			Schema.assert('route', hapiAuthorizationParams, 'Invalid settings');
		}
	});
};

/**
 * Checks if hapi-authorization is active for the current route and execute the necessary steps accordingly.
 *
 * @param request
 * @param h Hapi Reponse Toolkit https://hapijs.com/api#response-toolkit
 */
internals.onPreHandler = async (request, h) => {

  // Ignore OPTIONS requests
  if (request.route.method === 'options') {
    return h.continue;
  }

  let params;
  try {
    // Check if the current route is hapi-authorization enabled
    params = internals.getRouteParams(request);
  }
  catch (err) {
    return Boom.badRequest(err.message);
  }

  // if hapi-authorization is enabled, get the user
  if (params) {

    const user = request.auth.credentials;

    if (!request.plugins[pluginName]) {
      request.plugins[pluginName] = {};
    }

    let roleHierarchy = null;

    // If we're not using hierarchy
    if (!!this.config && this.config.hierarchy === true) {
      // this.config comes from plugin.bind
      roleHierarchy = this.config.roleHierarchy;
    } else {
      roleHierarchy = false;
    }

    try {
      // Checks roles
      if (params.role || params.roles) {
        const err = ACL.checkRoles(user, params.role || params.roles, roleHierarchy);
        if (err) {
          throw err;
        }
      }

      // Fetches acl entities
      let entity = null;
      if (params.aclQuery) {
        const parameter = request[params.paramSource][params.aclQueryParam];
        entity          = await ACL.fetchEntity(params.aclQuery, parameter, request);
      }

      // Store the entity
      if (entity) {
        request.plugins[pluginName].entity = entity;
      }
      // Validate the ACL settings

      if (params.validateEntityAcl) {
        if (!entity) {
          return new Error('Entity is required');
        }

        await ACL.validateEntityAcl(user, params.role || params.roles, entity, params.validateAclMethod, params);
      }
      return h.continue;
      // Handles errors
    } catch (err) {
      return err;
    }
  } else {
    return h.continue;
  }
};

/**
 * Returns the plugin params for the current request
 *
 * @param request
 * @returns {*}
 */
internals.getRouteParams = (request) => {

	if (request.route.settings.plugins[pluginName]) {
		const params = request.route.settings.plugins[pluginName];
		return Schema.assert('route', params, 'Invalid settings');
	} else {
		return null;
	}
};
