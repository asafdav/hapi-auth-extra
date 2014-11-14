/**
 * The default roles and role hierarchy if a custom one isn't passed in
 */

// The default roles
var RoleTypes = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  ADMIN: 'ADMIN',
  USER: 'USER',
  GUEST: 'GUEST'
};

// The default role hierarchy
var RoleHierarchy = {};
RoleHierarchy[RoleTypes.SUPER_ADMIN]	= [RoleTypes.SUPER_ADMIN, RoleTypes.ADMIN, RoleTypes.USER, RoleTypes.GUEST];
RoleHierarchy[RoleTypes.ADMIN]				= [RoleTypes.ADMIN, RoleTypes.USER, RoleTypes.GUEST];
RoleHierarchy[RoleTypes.USER]					= [RoleTypes.USER, RoleTypes.GUEST];
RoleHierarchy[RoleTypes.GUEST]				= [RoleTypes.GUEST];


//console.log('RoleHierarchy');
//console.log(RoleHierarchy);
//console.log(RoleHierarchy['SUPER_ADMIN'])

module.exports = {
  roles: RoleTypes,
  hierarchy: RoleHierarchy
};