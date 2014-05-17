// TODO - generalize

var RoleTypes = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  ADMIN: 'ADMIN',
  USER: 'USER',
  GUEST: 'GUEST'
};


var RoleHierarchy = {};
RoleHierarchy[RoleTypes.SUPER_ADMIN]  = [RoleTypes.SUPER_ADMIN, RoleTypes.ADMIN, RoleTypes.USER, RoleTypes.GUEST];
RoleHierarchy[RoleTypes.ADMIN]        = [RoleTypes.ADMIN, RoleTypes.USER, RoleTypes.GUEST];
RoleHierarchy[RoleTypes.USER]       = [RoleTypes.USER, RoleTypes.GUEST];
RoleHierarchy[RoleTypes.GUEST]       = [RoleTypes.GUEST];

module.exports = {
  roles: RoleTypes,
  hierarchy: RoleHierarchy
};