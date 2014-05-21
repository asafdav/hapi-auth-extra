/**
 * Created by asafdav on 18/05/14.
 */
var Joi = require('joi');
var Hoek = require('hoek');

// Internals
var internals = {};

exports.assert = function (type, options, message) {

  var validationObj = Joi.validate(options, internals[type]);
  var error = validationObj.error;
  Hoek.assert(!error, 'Invalid', type, 'options', message ? '(' + message + ')' : '', error && error.annotate());
  return validationObj.value;
};


internals.route = Joi.object({
  role: Joi.string(),
  aclQuery: Joi.func().when('validateEntityAcl', {is: true, then: Joi.required()}),
  aclQueryParam: Joi.string().default('id'),
  paramSource: Joi.string().allow('payload', 'params', 'query').default('params'),
  validateEntityAcl: Joi.boolean().default(false),
  validateAclMethod: Joi.string().default('isGranted')
}).options({ allowUnknown: false });