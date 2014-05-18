var Hoek = require('hoek');
var Hapi = require('hapi');

var Roles = require('./roles');
var Schema = require('./schema');
var ACL = require('./acl');

var pluginName = 'hapi-auth-extra';
var internals = {
  defaults: {
    roles: Roles.roles
  }
};

/**
 * Registers the plugin
 * @param plugin
 * @param options
 * @param next
 */
exports.register = function (plugin, options, next) {
  var settings = Hoek.applyToDefaults(internals.defaults, options || {});

  plugin.bind({
    config: settings
  });

  plugin.after(internals.validateRoutes);
  plugin.ext('onPostAuth', internals.onPostAuth);

  next();
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
  }
  catch (err) {
    next(err);
  }
  next();
};

/**
 * Checks if auth-extra is active for the current route and execute the necessary steps accordingly.
 * @param request
 * @param next
 */
internals.onPostAuth = function(request, next) {
  // Check if the current route is auth-extra enabled
  var params = internals.getRouteParams(request);
  if (params) {
    // auth-extra is enabled, get the user
    var err = null;
    var user = request.auth.credentials;

    if (!err && params.role) err = ACL.checkRoles(user, params.role);

    next(err);
  } else {
    next();
  }
};

/**
 * Returns the plugin params for the current request
 * @param request
 * @returns {*}
 */
internals.getRouteParams = function(request) {
  return !!request.route.plugins[pluginName] ? request.route.plugins[pluginName] : null;
};