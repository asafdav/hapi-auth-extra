/**
 * Created by asafdav on 18/05/14.
 */
var Joi = require('joi');
var Hoek = require('hoek');

// Internals
var internals = {};

exports.assert = function (type, options, message) {

  var error = Joi.validate(options, internals[type]);
  Hoek.assert(!error, 'Invalid', type, 'options', message ? '(' + message + ')' : '', error && error.annotated());
};


internals.route = Joi.object({
  roles: Joi.array()
}).options({ allowUnknown: false });