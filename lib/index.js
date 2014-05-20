var Hoek = require('hoek');
var Hapi = require('hapi');
var Q = require('q');

var Roles = require('./roles');
var Schema = require('./schema');
var ACL = require('./acl');
var Auth = require('./auth');

var pluginName = 'hapiAuthExtra';
var internals = {
  defaults: {
    roles: Roles.roles,
    tokenAuth: false
  }
};

/**
 * Registers the plugin
 * @param plugin
 * @param options
 * @param next
 */
exports.register = function (plugin, options, next) {
  try {
    var settings = Hoek.applyToDefaults(internals.defaults, options || {});

    plugin.bind({
      config: settings
    });

    plugin.after(internals.validateRoutes);
    plugin.ext('onPostAuth', internals.onPostAuth);

    if (settings.tokenAuth) Auth.register(plugin, settings.tokenAuth);

    next();
  } catch (e) {
    next(e);
  }
};

/**
 * Runs on server start and validates that every route that has extra-auth-params is valid
 * @param plugin
 * @param next
 */
internals.validateRoutes = function(plugin, next) {
  try {
    plugin.servers.forEach(function(server) {
      var routes = (server.routingTable) ? server.routingTable() : server.table();
      routes.forEach(function(route) {
        var extraAuthParams = route.settings.plugins[pluginName] ? route.settings.plugins[pluginName] : false;
        if (!!extraAuthParams) {
          Hoek.assert(!!route.settings.auth && route.settings.auth !== null, 'extra-auth can be enabled only for secured route');
          Schema.assert('route', extraAuthParams, 'Invalid settings');
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
 * Checks if auth-extra is active for the current route and execute the necessary steps accordingly.
 * @param request
 * @param next
 */
internals.onPostAuth = function(request, next) {
  try {
    // Check if the current route is auth-extra enabled
    var params = internals.getRouteParams(request);
    if (params) {
      // auth-extra is enabled, get the user
      var err = null;
      var user = request.auth.credentials;
      if (!request.plugins[pluginName]) request.plugins[pluginName] = {};

      Q
        // Checks roles
        .fcall(function () {
          if (params.role && !params.validateUserAcl) {
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
          if (entity) request.app.entity = entity;
          if (entity) {
            request.plugins[pluginName].entity = entity;
            return entity;
          }
        })
        // Validate the ACL settings
        .then(function(entity) {
          if (params.validateEntityAcl) {
            if (!entity) throw new Error('Entity is required');

            return ACL.validateEntityAcl(user, params.role, entity, params['validateAclMethod']);
          }
          return null;
        })
        // Handles errors
        .catch(function (err) {
          next(err);
        })
        .done(function () {
          next();
        });

      next(err);
    } else {
      next();
    }
  }
  catch (err) {
    next(Hapi.error.badRequest(err.message));
  }};

/**
 * Returns the plugin params for the current request
 * @param request
 * @returns {*}
 */
internals.getRouteParams = function(request) {
  if (!!request.route.plugins[pluginName]) {
    var params = request.route.plugins[pluginName];
    return Schema.assert('route', params, 'Invalid settings');
  } else {
    return null;
  }
};