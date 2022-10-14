===================
PyAMS LDAP authentication package package
===================

Introduction
------------

This package is composed of a set of utility functions, usable into any Pyramid application.

    >>> from pyramid.testing import setUp, tearDown, DummyRequest
    >>> config = setUp(hook_zca=True)

    >>> config = setUp(hook_zca=True)
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from cornice import includeme as include_cornice
    >>> include_cornice(config)
    >>> from pyams_utils import includeme as include_utils
    >>> include_utils(config)
    >>> from pyams_site import includeme as include_site
    >>> include_site(config)
    >>> from pyams_catalog import includeme as include_catalog
    >>> include_catalog(config)
    >>> from pyams_security import includeme as include_security
    >>> include_security(config)
    >>> from pyams_auth_ldap import includeme as include_auth_ldap
    >>> include_auth_ldap(config)

    >>> from pyams_utils.registry import get_utility, set_local_registry
    >>> registry = config.registry
    >>> set_local_registry(registry)

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))

    >>> from pyams_security.interfaces import ISecurityManager
    >>> sm = get_utility(ISecurityManager)

LDAP plugin is also using a short lifetime cache to store some properties:

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 0}})
    >>> cache_regions.update({'long': {'type': 'memory', 'expire': 0}})


LDAP authentication
-------------------

Let's try to create a custom LDAP plugin, to mock an LDAP connection:

    >>> from ldap3 import Connection, MOCK_ASYNC
    >>> from pyams_auth_ldap.plugin import LDAP_MANAGERS, LDAPPlugin, ConnectionManager

    >>> class FakeConnectionManager(ConnectionManager):
    ...     def get_connection(self, user=None, password=None, read_only=True):
    ...         return Connection(self.server, user=user, password=password,
    ...                           client_strategy=MOCK_ASYNC,
    ...                           auto_bind=True,
    ...                           lazy=False,
    ...                           read_only=read_only)

    >>> class FakeLDAPPlugin(LDAPPlugin):
    ...     connection_manager_class = FakeConnectionManager

We can now create a new plugin:

    >>> plugin = FakeLDAPPlugin()
    >>> plugin.prefix = 'ldap'
    >>> plugin.server_uri = 'ldap://localhost:389'
    >>> plugin.base_dn = 'o=pyams.org'

    >>> sm['ldap'] = plugin

Default LDAP plugin settings are defined so that user authentication relies on a
"uid" attribute used as username; you can change settings to login using one or several
alternate attributes, for example to allow authentication using UID or email address.

    >>> connection = plugin.get_connection()
    >>> _ = connection.strategy.add_entry('uid=admin,o=pyams.org', {
    ...     'userPassword': 'my_password',
    ...     'sn': ['Admin'],
    ...     'givenName': ['user'],
    ...     'uid': ['admin'],
    ...     'objectClass': ['user', 'person'],
    ...     'mail': ['admin@pyams.org'],
    ...     'revision': 0
    ... })

    >>> plugin.enabled
    True
    >>> plugin.login_attribute
    'uid'
    >>> plugin.uid_attribute
    'dn'

Please note that *ldap3* packages doesn't allow you to define entries containing spaces in their
DN; but if you relies on an LDAP server that allows them, that should be handled correctly by
PyAMS LDAP authentication plugin.


Let's try to authenticate using some credentials:

    >>> from pyams_security.credential import Credentials

We can start using an unknown principal:

    >>> creds = Credentials(prefix='http', id='unknown',
    ...                     login='unknown', password='')

    >>> plugin.authenticate(creds, None) is None
    True
    >>> plugin.get_principal('prefix:bob') is None
    True

    >>> creds = Credentials(prefix='http', id='admin',
    ...                     login='admin', password='my_password')

    >>> plugin.authenticate(creds, None)
    'ldap:uid=admin,o=pyams.org'

We can change plugin UID attribute:

    >>> plugin.uid_attribute = 'uid'
    >>> plugin.authenticate(creds, None)
    'ldap:admin'

    >>> ldap_user = plugin.get_principal('ldap:admin', info=False)
    >>> ldap_user
    <pyams_auth_ldap.plugin.LDAPUserInfo object at 0x...>

    >>> principal = plugin.get_principal('ldap:admin')
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> principal.id
    'ldap:admin'

We can get email address from LDAP user info:

    >>> from pyams_mail.interfaces import IPrincipalMailInfo
    >>> IPrincipalMailInfo(ldap_user).get_addresses()
    {('user Admin', 'admin@pyams.org')}


LDAP plugin also handles LDAP groups as principals; the first way to handle groups is to use a
group attribute to set its members:

    >>> _ = connection.strategy.add_entry('cn=admin-groups,ou=groups,o=pyams.org', {
    ...     'cn': ['admin-groups'],
    ...     'sn': ['Admin group'],
    ...     'objectClass': ['groupOfUniqueNames'],
    ...     'uniqueMember': ['uid=admin,o=pyams.org'],
    ...     'mail': ['admins-group@pyams.org'],
    ...     'revision': 0
    ... })

    >>> principal = plugin.get_principal('ldap:group:cn=admin-groups,ou=groups,o=pyams.org')
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> principal.id
    'ldap:group:cn=admin-groups,ou=groups,o=pyams.org'

    >>> group_info = plugin.get_principal('ldap:group:cn=admin-groups,ou=groups,o=pyams.org',
    ...                                   info=False)
    >>> group_info
    <pyams_auth_ldap.plugin.LDAPGroupInfo object at 0x...>
    >>> group_info.dn
    'cn=admin-groups,ou=groups,o=pyams.org'

Getting a group email address is possible; this can be based on a group attribute, or on an
attribute of its members:

    >>> from pyams_auth_ldap.interfaces import NO_GROUP_MAIL_MODE, INTERNAL_GROUP_MAIL_MODE
    >>> plugin.group_mail_mode = NO_GROUP_MAIL_MODE
    >>> list(IPrincipalMailInfo(group_info).get_addresses())
    [('user Admin', 'admin@pyams.org')]

    >>> plugin.group_mail_mode = INTERNAL_GROUP_MAIL_MODE
    >>> list(IPrincipalMailInfo(group_info).get_addresses())
    [('admin-groups', 'admins-group@pyams.org')]

    >>> plugin.get_all_principals('ldap:admin')
    {'ldap:admin'}

    >>> plugin.groups_base_dn = 'ou=groups,o=pyams.org'
    >>> sorted(plugin.get_all_principals('ldap:admin'))
    ['ldap:admin', 'ldap:group:cn=admin-groups,ou=groups,o=pyams.org']

    >>> from pyams_auth_ldap.plugin import LDAPGroupInfo
    >>> group = LDAPGroupInfo('cn=admin-groups,ou=groups,o=pyams.org', {}, plugin)
    >>> sorted([member.id for member in group.get_members()])
    ['ldap:uid=admin,o=pyams.org']

Another way is to set a user attribute to define all the groups to which he belongs; this
method is used by Active Directory servers:

    >>> _ = connection.strategy.add_entry('uid=admin2,o=pyams.org', {
    ...     'userPassword': 'my_password2',
    ...     'sn': ['Admin 2'],
    ...     'givenName': ['Admin user 2'],
    ...     'uid': ['admin2'],
    ...     'objectClass': ['user', 'person'],
    ...     'memberOf': ['cn=admin-groups,ou=groups,o=pyams.org'],
    ...     'revision': 0
    ... })

    >>> plugin.get_all_principals('ldap:admin2')
    {'ldap:admin2'}

We have to change plugin "group members query mode" from "group" to "member" to use this new
mode:

    >>> from pyams_auth_ldap.interfaces import QUERY_MEMBERS_FROM_MEMBER
    >>> plugin.group_members_query_mode = QUERY_MEMBERS_FROM_MEMBER
    >>> sorted(plugin.get_all_principals('ldap:admin2'))
    ['ldap:admin2', 'ldap:group:cn=admin-groups,ou=groups,o=pyams.org']

    >>> group_info = plugin.get_principal('ldap:group:cn=admin-groups,ou=groups,o=pyams.org', info=False)
    >>> group_info
    <pyams_auth_ldap.plugin.LDAPGroupInfo object at 0x...>
    >>> sorted((principal.id for principal in plugin.get_members(group_info)))
    ['ldap:admin2']
    >>> sorted((principal.dn for principal in plugin.get_members(group_info, info=False)))
    ['uid=admin2,o=pyams.org']


Other LDAP queries
------------------

LDAP authentication plugin can be used to search principals:

    >>> plugin.users_select_query = '(&(objectClass=user)(|(givenName={query}*)(sn={query}*)))'
    >>> list(plugin.find_principals(''))
    []

    >>> sorted([principal.id for principal in plugin.find_principals('admin')])
    ['ldap:admin', 'ldap:admin2', 'ldap:group:cn=admin-groups,ou=groups,o=pyams.org']

    >>> list(plugin.get_search_results({}))
    []

    >>> sorted((dn for dn, attrs in sorted(plugin.get_search_results({'query': 'admin'}))))
    ['cn=admin-groups,ou=groups,o=pyams.org', 'cn=admin-groups,ou=groups,o=pyams.org',
     'uid=admin,o=pyams.org', 'uid=admin2,o=pyams.org']


Tests cleanup:

    >>> tearDown()
