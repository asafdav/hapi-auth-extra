var Hoek = require('hoek');
var Hapi = require('hapi');
var Q = require('q');

var Roles = require('./roles');
var Schema = require('./schema');
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
	console.log('in register');
  try {
    var settings = Hoek.applyToDefaults(internals.defaults, options || {});

		console.log('here');
		//console.log(settings);

    plugin.bind({
      config: settings
    });

		console.log('asdf');
		console.log(plugin.config);

    plugin.after(internals.validateRoutes);

    plugin.ext('onPostAuth', internals.onPostAuth);

    //if (settings.tokenAuth) Auth.register(plugin, settings.tokenAuth);

    next();
  } catch (e) {
    next(e);
  }
};

/**
 * Runs on server start and validates that every route that has hapi-authorization params is valid
 *
 * @param plugin
 * @param next
 */
internals.validateRoutes = function(plugin, next) {

	console.log('in validateRoutes');
  try {
    plugin.servers.forEach(function(server) {
      var routes = (server.routingTable) ? server.routingTable() : server.table();
      routes.forEach(function(route) {
        var extraAuthParams = route.settings.plugins[pluginName] ? route.settings.plugins[pluginName] : false;

				console.log(extraAuthParams);

				console.log(!!extraAuthParams);

        if (extraAuthParams) {
          Hoek.assert(route.settings.auth && route.settings.auth !== null, 'extra-auth can be enabled only for secured route');
          Schema.assert('route', extraAuthParams, 'Invalid settings');
        }
      });
    });

    next();
  }
  catch (err) {
		console.log('in catch');
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

		//console.log(request);

    // Check if the current route is hapi-authorization enabled
    var params = internals.getRouteParams(request);

		console.log('params = ');
		console.log(params);

    if (params) {
      // hapi-authorization is enabled, get the user
      var err = null;
      var user = request.auth.credentials;

			console.log('user = ');
			console.log(user);

      if (!request.plugins[pluginName]) {
				request.plugins[pluginName] = {};
			}



      Q
        // Checks roles
        .fcall(function () {

						console.log('params.role = ');
						console.log(params.role);

          if (params.role && !params.validateUserAcl) {
						console.log('inside this');
            var err = ACL.checkRoles(user, params.role);
            if (err) throw err;
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
            if (!entity) throw new Error('Entity is required');

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

		console.log('in if');
    var params = request.route.plugins[pluginName];
		console.log('params = ');
		console.log(params);
		console.log('schema.assert = ');
		console.log(Schema.assert('route', params, 'Invalid settings'));
    return Schema.assert('route', params, 'Invalid settings');
  } else {
    return null;
  }
};