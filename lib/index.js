var Hoek = require('hoek');
var Hapi = require('hapi');
var Q = require('q');

var Roles = require('./roles');
var Schema = require('./schema');
var RoleHierarchy = Roles.hierarchy;
var ACL = require('./acl');

var pluginName = 'hapiAuthorization';
var internals = {
  defaults: {
    roles: Roles.roles
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

	//console.log('options = ');
	//console.log(options)

  try {
		// Validate the options passed into the plugin
		Schema.assert('plugin', options, 'Invalid settings');

    var settings = Hoek.applyToDefaults(internals.defaults, options || {});

    plugin.bind({
      config: settings
    });

		// Validate the plugin options on the routes
    plugin.after(internals.validateRoutes);
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


	console.log('in validateRoutes');

	//console.log(plugin);
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

/**
 * Checks if hapi-authorization is active for the current route and execute the necessary steps accordingly.
 *
 * @param request
 * @param next
 */
internals.onPostAuth = function(request, next) {

	console.log('in onPostAuth');

  try {

    // Check if the current route is hapi-authorization enabled
    var params = internals.getRouteParams(request);



		// if hapi-authorization is enabled, get the user
    if (params) {



      var user = request.auth.credentials;

      if (!request.plugins[pluginName]) {
				request.plugins[pluginName] = {};
			}

			console.log('params = ');
			console.log(params);

      Q
        // Checks roles
        .fcall(function () {
						console.log('in fcall');
          if (params.role && !params.validateUserAcl) {
						console.log('after fcall');
						console.log('user = ');
						console.log(user);
						console.log('params.role =');
						console.log(params.role);
						console.log('params.roles = ');
						console.log(params.roles);
						console.log('RoleHierarchy = ');
						console.log(RoleHierarchy);
            var err = ACL.checkRoles(user, params.role || params.roles, RoleHierarchy);
						console.log('after checkRoles');
            if (err) throw err;
          }
          return true;
        })
        // Fetches acl entities
        .then(function () {
						console.log('in 1st then');
          if (params.aclQuery) {
            var parameter = request[params.paramSource][params.aclQueryParam];
            return ACL.fetchEntity(params.aclQuery, parameter, request);
          }
          return null;
        })
        // Store the entity
        .then(function(entity) {
						console.log('in 2nd then');
          if (entity) {
            request.plugins[pluginName].entity = entity;
            return entity;
          }
        })
        // Validate the ACL settings
        .then(function(entity) {
						console.log('in 3rd then');
          if (params.validateEntityAcl) {
            if (!entity) throw new Error('Entity is required');

            return ACL.validateEntityAcl(user, params.role, entity, params['validateAclMethod'], params);
          }
          return null;
        })
        .then(function () {
						console.log('in last then');
          next();
        })
        // Handles errors
        .catch(function (err) {
						console.log('in catch');
						console.log(err);
          next(err);
        });

    } else {
      next();
    }
  }
  catch (err) {
    next(Hapi.error.badRequest(err.message));
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