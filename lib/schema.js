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
  return options;
};


internals.route = Joi.object({
  role: Joi.string(),
  aclQuery: Joi.func(),
  aclQueryParam: Joi.string().default('id'),
  paramSource: Joi.string().allow('payload', 'params', 'query').default('params')
}).options({ allowUnknown: false });