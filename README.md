# hapi-authorization

> ACL support for hapijs apps

[![Build Status](https://travis-ci.org/toymachiner62/hapi-authorization.svg)](https://travis-ci.org/toymachiner62/hapi-authorization)

### Support
Hapi >= 6

# Usage

### ACL
You can use this plugin to add ACL and protect your routes. you can configure required roles and allow access to certain endpoints only to specific users.

In order to activate the plugin for a specific route, all you have to do is to add hapiAuthExtra instructions to the route configuration, for example: 

```javascript
server.route({ method: 'GET', path: '/', config: {
  auth: true,
  plugins: {'hapiAuthExtra': {role: 'ADMIN'}},
  handler: function (request, reply) { reply("Great!");}
}});
```

**Note:** every route that uses hapiAuthExtra must be protected by an authentication schema (auth: true).

#### Examples

* Protected by role
You can protect a route and set a role that is required for executing it. 
The following example makes sure that only admins will be able to create new products. 

```javascript
server.route({ method: 'POST', path: '/product', config: {
  auth: true, // Protected route
  plugins: {'hapiAuthExtra': {role: 'ADMIN'}}, // Only admin 
  handler: function (request, reply) { reply({title: 'New product'}).code(201);} 
}});
```

* Default entity ACL
You can protect a route and allow only the entitiy's creator to modify it.
The following example makes sure that only the video owner will be able to delete it.

```javascript
server.route({ method: 'DELETE', path: '/video/{id}', config: {
      auth: true, // Protected route
      plugins: {'hapiAuthExtra': {
        validateEntityAcl: true, // Validate the entity ACL
        aclQuery: function(id, cb) { // This query is used to fetch the entitiy, by default auth-extra will verify the field _user.
          cb(null, {_user: '1', name: 'Hello'}); // You can use and method you want as long as you keep this signature.
        }
      }},
      handler: function (request, reply) { reply("Authorized");}
    }});
```

* Custom ACL
TBD

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
