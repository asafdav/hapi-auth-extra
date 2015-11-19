var Hoek = require('hoek');
var Boom = require('boom');
var Q = require('q');

var Roles = require('./roles');
var Schema = require('./schema');
var ACL = require('./acl');
var Auth = require('./auth');

var pluginName = 'hapiAuthExtra';
var internals = {
    defaults: {
        roles    : Roles.roles,
        tokenAuth: false
    }
};

/**
 * Registers the plugin
 * @param server
 * @param options
 * @param next
 */
exports.register = function (server, options, next) {
    try {
        var settings = Hoek.applyToDefaults(internals.defaults, options || {});

        server.bind({
            config: settings
        });

        server.after(internals.validateRoutes);
        server.ext('onPostAuth', internals.onPostAuth);

        if (settings.tokenAuth) Auth.register(server, settings.tokenAuth);

        return next();
    } catch (e) {
        return next(e);
    }
};

/**
 * Backward compatibility
 * @type {{pkg: exports}}
 */
exports.register.attributes = {
    pkg: require('../package.json')
};

/**
 * Backward compatibility
 * @type {{pkg: exports}}
 */
exports.register.attributes = {
  pkg: require('../package.json')
};

/**
 * Runs on server start and validates that every route that has extra-auth-params is valid
 * @param server
 * @param next
 */
internals.validateRoutes = function (server, next) {
    try {
        server.table().forEach(function (routingTable) {
            routingTable.table.forEach(function (table) {
                var extraAuthParams = table.settings.plugins[pluginName] ? table.settings.plugins[pluginName] : false;
                if (!!extraAuthParams) {
                    Hoek.assert(!!table.settings.auth && table.settings.auth !== null, 'extra-auth can be enabled only for secured route');
                    Schema.assert('route', extraAuthParams, 'Invalid settings');
                }
            });
        });
        next();
    } catch (err) {
        next(err);
    }
};

/**
 * Checks if auth-extra is active for the current route and execute the necessary steps accordingly.
 * @param request
 * @param reply
 */
internals.onPostAuth = function (request, reply) {
    try {
        // Check if the current route is auth-extra enabled
        var params = internals.getRouteParams(request);
        if (params) {
            // auth-extra is enabled, get the user
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
                .then(function (entity) {
                    if (entity) {
                        request.plugins[pluginName].entity = entity;
                        return entity;
                    }
                })
                // Validate the ACL settings
                .then(function (entity) {
                    if (params.validateEntityAcl) {
                        if (!entity) throw new Error('Entity is required');

                        return ACL.validateEntityAcl(user, params.role, entity, params['validateAclMethod'], params);
                    }
                    return null;
                })
                .then(function () {
                    reply.continue();
                })
                // Handles errors
                .catch(function (err) {
                    reply(err);
                });

        } else {
            reply.continue();
        }
    }
    catch (err) {
        //console.log(err);
        reply(Boom.badRequest(err.message));
    }
};

/**
 * Returns the plugin params for the current request
 * @param request
 * @returns {*}
 */
internals.getRouteParams = function (request) {
    if (!!request.route.settings.plugins[pluginName]) {
        var params = request.route.settings.plugins[pluginName];
        return Schema.assert('route', params, 'Invalid settings');
    } else {
        return null;
    }
};