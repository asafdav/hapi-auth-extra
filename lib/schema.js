var Joi = require('joi');
var Hoek = require('hoek');

// Internals
var internals = {};

/**
 * Assert that the plugin params are valid
 *
 * @param type
 * @param options
 * @param message
 * @returns {*}
 */
exports.assert = function (type, options, message) {

  var validationObj = Joi.validate(options, internals[type]);
  var error = validationObj.error;
	var errorMessage = null;

	// If there is an error, build a nice error message
	if(error) {
		errorMessage = error.name + ':';
		error.details.forEach(function(err) {
			errorMessage += ' ' + err.message;
		});
	}

	// If there is an error build the error message
	Hoek.assert(!error, 'Invalid', type, 'options', message ? '(' + message + ')' : '', errorMessage);

  return validationObj.value;
};

/**
 * Validation rules for the plugin params
 */
internals.route = Joi.object({
  role: Joi.string().optional(),
	roles: Joi.array().optional(),
  aclQuery: Joi.func().when('validateEntityAcl', {is: true, then: Joi.required()}),
  aclQueryParam: Joi.string().default('id'),
  paramSource: Joi.string().allow('payload', 'params', 'query').default('params'),
  validateEntityAcl: Joi.boolean().default(false),
  validateAclMethod: Joi.string().default(null),
  entityUserField: Joi.string().default("_user"),
  entityRoleField: Joi.string().default("role"),
  userIdField: Joi.string().default("_id"),
  userRoleField: Joi.string().default("role")
}).without('role', 'roles').options({ allowUnknown: false });