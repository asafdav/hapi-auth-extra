hapi-auth-extra
===============

[![Build Status](https://travis-ci.org/asafdav/hapi-auth-extra.svg?branch=master)](https://travis-ci.org/asafdav/hapi-auth-extra)

Additional authentication toolbox for HapiJS.

It includes: 
* ACL support
* Authentication strategy for APIs (Token based)

How to use it:
--------------

### Token authentication 

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

supported parameters: 
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
