var Roles = require('./roles');

var internals = {
  defaults: {
    roles: Roles
  }
};


exports.register = function (plugin, options, next) {
  var settings = Hoek.applyToDefaults(internals.defaults, options || {});

  plugin.bind({
    config: settings
  });

  plugin.ext('onPostAuth', internals.onPostAuth);

  next();
};

internals.onPostHandler = function(request, next) {
  next();
};