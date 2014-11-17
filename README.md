# hapi-authorization

> ACL support for hapijs apps

[![Build Status](https://travis-ci.org/toymachiner62/hapi-authorization.svg)](https://travis-ci.org/toymachiner62/hapi-authorization)

You can use this plugin to add ACL and protect your routes. you can configure required roles and allow access to certain endpoints only to specific users.

### Support
Hapi >= 6

# Usage

**Note**: To use hapi-authorization you must have an authentication strategy defined.

There are 2 ways to use hapi-authorization:

1. With the default roles which are: "SUPER_ADMIN", "ADMIN", "USER", "GUEST"
2. By defining your own roles

## Using hapi-authorization with default roles
1. Include the plugin in your hapijs app.
Example:
```js
var plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('hapi-authorization')
	}
];

server.pack.register(plugins, function(err) {
...
```

## Using hapi-authorization with custom roles
1. Include the plugin in your hapijs app.
Example:
```js
var plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('hapi-authorization'),
		options: {
			roles: ['OWNER', 'MANAGER', 'EMPLOYEE']	// Can also reference a function which returns an array of roles
		}
	}
];

server.pack.register(plugins, function(err) {
...
```

In order to activate the plugin for a specific route, add hapiAuthorization instructions with the role(s) that should have access to the route configuration.

Example:

**Authorize a single role**
```js
server.route({ method: 'GET', path: '/', config: {
  auth: 'someAuthStrategy',
  plugins: {'hapiAuthorization': {role: 'ADMIN'}},
  handler: function (request, reply) { reply("Great!");}
}});
```

**Authorize multiple roles**
```js
server.route({ method: 'GET', path: '/', config: {
  auth: 'someAuthStrategy',
  plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
  handler: function (request, reply) { reply("Great!");}
}});
```

**Note:** Every route that uses hapiAuthorization must be protected by an authentication schema on the route itself (auth: 'someAuthStrategy'). Currently can't just use `auth.strategy.default()`

#### Examples

* Protected by role
You can protect a route and set a role that is required for executing it. 
The following example makes sure that only admins will be able to create new products. 

```javascript
server.route({ method: 'POST', path: '/product', config: {
  auth: true, // Protected route
  plugins: {'hapiAuthorization': {role: 'ADMIN'}}, // Only admin
  handler: function (request, reply) { reply({title: 'New product'}).code(201);} 
}});
```

* Default entity ACL
You can protect a route and allow only the entitiy's creator to modify it.
The following example makes sure that only the video owner will be able to delete it.

```javascript
server.route({ method: 'DELETE', path: '/video/{id}', config: {
      auth: true, // Protected route
      plugins: {'hapiAuthorization': {
        validateEntityAcl: true, // Validate the entity ACL
        aclQuery: function(id, cb) { // This query is used to fetch the entitiy, by default hapi-authorization will verify the field _user.
          cb(null, {_user: '1', name: 'Hello'}); // You can use and method you want as long as you keep this signature.
        }
      }},
      handler: function (request, reply) { reply("Authorized");}
    }});
```

* Custom ACL
TBD

### Example using hapi-auth-basic

```js
var Hapi = require('hapi');
var modules = require('./modules');

// Instantiate the server
var server = new Hapi.Server('0.0.0.0', 3000, {cors: true, debug: {request: ['error']}});

/**
 * The hapijs plugins that we want to use and their configs
 */
var plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('hapi-authorization'),
		options: {
			roles: ['OWNER', 'MANAGER', 'EMPLOYEE']
		}
	}
];

var validate = function(username, password, callback) {
	// Perform authentication and callback with object that contains a role or an array of roles
	callback(null, true, {username: username, role: 'EMPLOYEE'});
}

/**
 * Setup the server with plugins
 */
server.pack.register(plugins, function(err) {

  // If there is an error on server startup
  if(err) {
    throw err;
  }

	server.auth.strategy('simple', 'basic', {validateFunc: validate});
	server.auth.default('simple');

	/**
	 * Add all the modules within the modules folder
	 */
	for(var route in modules) {
		server.route(modules[route]);
	}

	/**
	 * Starts the server
	 */
	server.start(function (err) {

		if(err) {
			console.log(err);
		}

		console.log('Hapi server started @', server.info.uri);
	});
});
```

Full list of supported parameters: 
--------------------
* role - String: enforces that only users that has this role can access the route
* aclQuery - Function: fetches an entity using the provided query, it allows the plugin to verify that the authenticated user has permissions to access this entity. the function signature should be function(parameter, cb).
* aclQueryParam: String: The parameter key that will be used to fetch the entity. default: 'id'
* paramSource: String: The source of the acl parameter, allowed values: payload, params, query.
* validateEntityAcl: Boolean: Should the plugin validate if the user has access to the entity. if true, validateAclMethod is required. 
* validateAclMethod: String: A function name. the plugin will invoke this method on the provided entity and will use it to verify that the user has permissions to access this entity. function signature is function(user, role, cb);


### TODO
* Write an example (For now, see the tests for more information)
* Add output filtering
