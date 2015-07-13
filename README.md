# hapi-authorization

> ACL support for hapijs apps

[![Build Status](https://travis-ci.org/toymachiner62/hapi-authorization.svg?branch=master)](https://travis-ci.org/toymachiner62/hapi-authorization)

You can use this plugin to add ACL and protect your routes. you can configure required roles and allow access to certain endpoints only to specific users.

### Support
Hapi >= 6 < 8	- Use version 1.x  
Hapi >= 8			- Use version 2.x

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
		register: require('hapi-auth-basic')
	},
	{
		register: require('hapi-authorization')
		options: {
		  roles: false	// By setting to false, you are not using an authorization hierarchy and you do not need to specify all the potential roles here
		}
	}
];

server.register(plugins, function(err) {
...
```

## Using hapi-authorization with custom roles
1. Include the plugin in your hapijs app.
Example:
```js
var plugins = [
	{
		register: require('hapi-auth-basic')
	},
	{
		register: require('hapi-authorization'),
		options: {
			roles: ['OWNER', 'MANAGER', 'EMPLOYEE']	// Can also reference a function which returns an array of roles
		}
	}
];

server.register(plugins, function(err) {
...
```

#### Whitelist Routes That Require Authorization
If you want no routes require authorization except for the ones you specify in the route config, add hapiAuthorization instructions with the role(s) that should have access to the route configuration.

Example:

**Authorize a single role**
```js
server.route({ method: 'GET', path: '/', config: {
  plugins: {'hapiAuthorization': {role: 'ADMIN'}},	// Only ADMIN role
  handler: function (request, reply) { reply("Great!");}
}});
```

**Authorize multiple roles**
```js
server.route({ method: 'GET', path: '/', config: {
  plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
  handler: function (request, reply) { reply("Great!");}
}});
```

#### Blacklist All Routes To Require Authorization

If you want all routes to require authorization except for the ones you specify that should not, add hapiAuthorization instructions with the role(s) that should have access to the server.connection options. Note that these can be overridden on each route individually as well.

Example:

```js
var server = new Hapi.server();
server.connection({
	routes: {
		plugins: {
			hapiAuthorization: { roles: ['ADMIN'] }
		}
	}
});
```

**Override the authorization to require alternate roles**
```js
server.route({ method: 'GET', path: '/', config: {
  plugins: {'hapiAuthorization': {role: 'USER'}},	// Only USER role
  handler: function (request, reply) { reply("Great!");}
}});
```

**Override the authorization to not require any authorization**
```js
server.route({ method: 'GET', path: '/', config: {
  plugins: {'hapiAuthorization': false},
  handler: function (request, reply) { reply("Great!");}
}});
```


**Note:** Every route that uses hapiAuthorization must be protected by an authentication schema either via `auth.strategy.default('someAuthStrategy')` or by specifying the auth on the route itself.

## Full Example using hapi-auth-basic and hapi-authorization

```js
var Hapi = require('hapi');
var modules = require('./modules');

// Instantiate the server
var server = new Hapi.Server();
server.connection();

/**
 * The hapijs plugins that we want to use and their configs
 */
var plugins = [
	{
		register: require('hapi-auth-basic')
	},
	{
		register: require('hapi-authorization'),
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
server.register(plugins, function(err) {

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

## Gotchas

### Auth before routes
You must define your auth strategy before defining your routes, otherwise the route validation will fail.


## Plugin Config

* `roles` 				- `Array|false`: All the possible roles. Defaults to `SUPER_ADMIN`, `ADMIN`, `USER`, `GUEST`. Can be set to `false` if no hierarchy is being used. by setting to `false` you do not need to know all the potential roles
* `hierarchy` 		- `Boolean`: An option to turn on or off hierarchy. Defaults to `false`
* `roleHierarchy` - `Array`: The role hierarchy. Roles with a lower index in the array have access to all roles with a higher index in the array.
		With the default roles, this means that `USER` has access to all roles restricted to `GUEST`,
		  `ADMIN` has access to all roles restricted to `USER` and `GUEST`, and
		  `SUPER_ADMIN` has access to all roles restricted to `ADMIN`, `USER`, and `GUEST`.


## Route config of supported parameters:
* `role` - `String`: enforces that only users that have this role can access the route
* `roles` - `Array`: enforces that only users that have these roles can access the route
* `aclQuery` - `Function`: fetches an entity using the provided query, it allows the plugin to verify that the authenticated user has permissions to access this entity. the function signature should be `function(parameter, cb)`.
* `aclQueryParam` - `String`: The parameter key that will be used to fetch the entity. default: 'id'
* `paramSource` - `String`: The source of the acl parameter, allowed values: payload, params, query.
* `validateEntityAcl` - `Boolean`: Should the plugin validate if the user has access to the entity. if true, validateAclMethod is required.
* `validateAclMethod` - `String`: A function name. the plugin will invoke this method on the provided entity and will use it to verify that the user has permissions to access this entity. function signature is `function(user, role, cb)`;
