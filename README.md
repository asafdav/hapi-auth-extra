# hapi-authorization

*hapi-authorization 4 only supports hapi 17+ for hapi 16 please use hapi-authorization 3*

> ACL support for hapijs apps

[![npm version][npm-badge]][npm-url]
[![Build Status][travis-badge]][travis-url]
[![Coverage Status][coveralls-badge]][coveralls-url]
[![Dev Dependencies][david-badge]][david-url]

You can use this plugin to add ACL and protect your routes. you can configure required roles and allow access to certain endpoints only to specific users.

### Support

- `Hapi >= 6 < 8`   - Use version `1.x`
- `Hapi >= 8 < 10`  - Use version `2.x`
- `Hapi >= 10`      - Use version `3.x`
- `Hapi >= 17`      - Use version `4.x`

# Usage

**Note**: To use hapi-authorization you must have an authentication strategy defined.

There are 2 ways to use hapi-authorization:

1. With the default roles which are: "SUPER_ADMIN", "ADMIN", "USER", "GUEST"
2. By defining your own roles

## Using hapi-authorization with default roles
1. Include the plugin in your hapijs app.
Example:
```js
let plugins = [
	{
		plugin: require('hapi-auth-basic')
	},
	{
		plugin: require('hapi-authorization')
		options: {
		  roles: false	// By setting to false, you are not using an authorization hierarchy and you do not need to specify all the potential roles here
		}
	}
];

await server.register(plugins);
```

## Using hapi-authorization with custom roles
1. Include the plugin in your hapijs app.
Example:
```js
let plugins = [
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

await server.register(plugins);
```

#### Whitelist Routes That Require Authorization
If you want no routes require authorization except for the ones you specify in the route config, add hapiAuthorization instructions with the role(s) that should have access to the route configuration.

Example:

**Authorize a single role**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hapiAuthorization': {role: 'ADMIN'}},	// Only ADMIN role
  handler: (request, h) => { return "Great!"; }
}});
```

**Authorize multiple roles**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hapiAuthorization': {roles: ['USER', 'ADMIN']}},
  handler: (request, h) => { return "Great!"; }
}});
```

#### Blacklist All Routes To Require Authorization

If you want all routes to require authorization except for the ones you specify that should not, add hapiAuthorization instructions with the role(s) that should have access to the server.connection options. Note that these can be overridden on each route individually as well.

Example:

```js
let server = new Hapi.server({
	routes: {
		plugins: {
			hapiAuthorization: { roles: ['ADMIN'] }
		}
	}
});
```

**Override the authorization to require alternate roles**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hapiAuthorization': {role: 'USER'}},	// Only USER role
  handler: (request, h) => { return "Great!" ;}
}});
```

**Override the authorization to not require any authorization**
```js
server.route({ method: 'GET', path: '/', options: {
  plugins: {'hapiAuthorization': false},
  handler: (request, h) => { return "Great!"; }
}});
```

**Note:** Every route that uses hapiAuthorization must be protected by an authentication schema either via `auth.strategy.default('someAuthStrategy')` or by specifying the auth on the route itself.

## Full Example using hapi-auth-basic and hapi-authorization

```js
const Hapi = require('hapi');
const modules = require('./modules');

// Instantiate the server
let server = new Hapi.Server();

/**
 * The hapijs plugins that we want to use and their configs
 */
let plugins = [
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

let validate = (username, password) => {
	// Perform authentication and respond with object that contains a role or an array of roles
	return {username: username, role: 'EMPLOYEE'};
}

/**
 * Setup the server with plugins
 */
await server.register(plugins);
server.start().then(() => {

	server.auth.strategy('simple', 'basic', {validateFunc: validate});
	server.auth.default('simple');

	/**
	 * Add all the modules within the modules folder
	 */
	for(let route in modules) {
		server.route(modules[route]);
	}

	/**
	 * Starts the server
	 */
	server.start()
        .then(() => {
            console.log('Hapi server started @', server.info.uri);
        })
        .catch((err) => {
            console.log(err);
        });
})
.catch((err) => {
  // If there is an error on server startup
  throw err;
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
* `aclQuery` - `Function`: fetches an entity using the provided query, it allows the plugin to verify that the authenticated user has permissions to access this entity. the function signature should be `function(parameter, request)`.
* `aclQueryParam` - `String`: The parameter key that will be used to fetch the entity. default: 'id'
* `paramSource` - `String`: The source of the acl parameter, allowed values: payload, params, query.
* `validateEntityAcl` - `Boolean`: Should the plugin validate if the user has access to the entity. if true, validateAclMethod is required.
* `validateAclMethod` - `String`: A function name. the plugin will invoke this method on the provided entity and will use it to verify that the user has permissions to access this entity. function signature is `function(user, role)`;


[npm-badge]: https://badge.fury.io/js/hapi-authorization.svg
[npm-url]: https://badge.fury.io/js/hapi-authorization
[travis-badge]: https://travis-ci.org/toymachiner62/hapi-authorization.svg?branch=master
[travis-url]: https://travis-ci.org/toymachiner62/hapi-authorization
[coveralls-badge]: https://coveralls.io/repos/toymachiner62/hapi-authorization/badge.svg?branch=master&service=github
[coveralls-url]:  https://coveralls.io/github/toymachiner62/hapi-authorization?branch=master
[david-badge]: https://david-dm.org/toymachiner62/hapi-authorization.svg
[david-url]: https://david-dm.org/toymachiner62/hapi-authorization
