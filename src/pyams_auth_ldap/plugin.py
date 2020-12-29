#
# Copyright (c) 2015-2020 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_auth_ldap.plugin module

This module defines the main LDAP authentication plug-in.
"""

import logging
import re

from beaker.cache import cache_region
from ldap3 import ALL_ATTRIBUTES, ASYNC, AUTO_BIND_DEFAULT, AUTO_BIND_NONE, BASE, Connection, \
    REUSABLE, Server
from ldap3.core.exceptions import LDAPBindError
from ldap3.utils.conv import escape_filter_chars
from persistent import Persistent
from pyams_auth_ldap.interfaces import ILDAPGroupInfo, ILDAPPlugin, ILDAPUserInfo
from pyams_auth_ldap.query import LDAPQuery
from zope.container.contained import Contained
from zope.interface import implementer
from zope.intid import IIntIds
from zope.schema.fieldproperty import FieldProperty

from pyams_mail.interfaces import IPrincipalMailInfo
from pyams_security.principal import PrincipalInfo
from pyams_utils.adapter import ContextAdapter, adapter_config
from pyams_utils.factory import factory_config
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'


LOGGER = logging.getLogger('PyAMS (ldap)')


managers = {}

FORMAT_ATTRIBUTES = re.compile("\{(\w+)\[?\d*\]?\}")


class ConnectionManager:
    """LDAP connections manager"""

    _connection = None

    def __init__(self, plugin):
        self.server = Server(plugin.host,
                             port=plugin.port,
                             use_ssl=plugin.use_ssl)
        self.bind_dn = plugin.bind_dn
        self.password = plugin.bind_password

    def get_connection(self, user=None, password=None, read_only=True):
        """Open LDAP connection"""
        if user:
            conn = Connection(self.server,
                              user=user, password=password,
                              client_strategy=ASYNC,
                              auto_bind=True,
                              lazy=False,
                              read_only=read_only)
        else:
            conn = self._connection
            if conn is None:
                bind_mode = AUTO_BIND_DEFAULT if self.bind_dn else AUTO_BIND_NONE
                conn = Connection(self.server,
                                  user=self.bind_dn, password=self.password,
                                  client_strategy=REUSABLE,
                                  auto_bind=bind_mode,
                                  lazy=True,
                                  read_only=read_only)
                if conn.auto_bind == AUTO_BIND_NONE:
                    conn.open(read_server_info=False)
                self._connection = conn
        return conn


@implementer(ILDAPUserInfo)
class LDAPUserInfo(object):
    """LDAP user info"""

    def __init__(self, dn, attributes, plugin=None):
        self.dn = dn
        self.attributes = attributes
        self.plugin = plugin


@adapter_config(required=ILDAPUserInfo, provides=IPrincipalMailInfo)
class LDAPUserMailInfoAdapter(ContextAdapter):
    """LDAP user mail adapter"""

    def get_addresses(self):
        """Get mail address of given user"""

        user = self.context
        plugin = user.plugin

        mail = user.attributes.get(plugin.mail_attribute)
        if mail:
            return {(plugin.title_format.format(**user.attributes),
                     mail[0] if isinstance(mail, (list, tuple)) else mail)}
        return set()


@implementer(ILDAPGroupInfo)
class LDAPGroupInfo:
    """LDAP group info"""

    def __init__(self, dn, attributes, plugin=None):
        self.dn = dn
        self.attributes = attributes
        self.plugin = plugin

    def get_members(self, info=True):
        return self.plugin.get_members(self, info=info)


@adapter_config(required=ILDAPGroupInfo, provides=IPrincipalMailInfo)
class LDAPGroupMailInfoAdapter(ContextAdapter):
    """LDAP group mail adapter"""

    def get_addresses(self):
        """Get mail address of given group"""

        group = self.context
        plugin = group.plugin

        if plugin.group_mail_mode == 'none':
            # use members address
            for member in plugin.get_members(group, info=False):
                mail_info = IPrincipalMailInfo(member, None)
                if mail_info is not None:
                    for address in mail_info.get_addresses():
                        yield address

        elif plugin.group_mail_mode == 'internal':
            # use group internal attribute
            mail = group.attributes.get(plugin.group_mail_attribute)
            if mail:
                yield plugin.group_title_format(**group.attributes), \
                      mail[0] if isinstance(mail, (list, tuple)) else mail

        else:
            # redirect: use internal attribute of another group
            source, target = plugin.group_replace_expression.split('|')
            target_dn = group.dn.replace(source, target)
            conn = plugin.get_connection()
            attributes = FORMAT_ATTRIBUTES.findall(plugin.group_title_format) + \
                         [plugin.group_mail_attribute]
            search = LDAPQuery(target_dn, '(objectClass=*)', BASE, attributes)
            result = search.execute(conn)
            if not result or len(result) > 1:
                raise StopIteration
            target_dn, attrs = result[0]
            mail = attrs.get(plugin.group_mail_attribute)
            if mail:
                yield plugin.group_title_format(**attrs), \
                      mail[0] if isinstance(mail, (list, tuple)) else mail


@factory_config(ILDAPPlugin)
class LDAPPlugin(Persistent, Contained):
    """LDAP authentication plug-in"""

    prefix = FieldProperty(ILDAPPlugin['prefix'])
    title = FieldProperty(ILDAPPlugin['title'])
    enabled = FieldProperty(ILDAPPlugin['enabled'])

    _scheme = None
    _host = None
    _port = None
    _use_ssl = False

    _server_uri = FieldProperty(ILDAPPlugin['server_uri'])
    bind_dn = FieldProperty(ILDAPPlugin['bind_dn'])
    bind_password = FieldProperty(ILDAPPlugin['bind_password'])

    base_dn = FieldProperty(ILDAPPlugin['base_dn'])
    search_scope = FieldProperty(ILDAPPlugin['search_scope'])

    login_attribute = FieldProperty(ILDAPPlugin['login_attribute'])
    login_query = FieldProperty(ILDAPPlugin['login_query'])
    uid_attribute = FieldProperty(ILDAPPlugin['uid_attribute'])
    uid_query = FieldProperty(ILDAPPlugin['uid_query'])
    title_format = FieldProperty(ILDAPPlugin['title_format'])
    mail_attribute = FieldProperty(ILDAPPlugin['mail_attribute'])
    user_extra_attributes = FieldProperty(ILDAPPlugin['user_extra_attributes'])

    groups_base_dn = FieldProperty(ILDAPPlugin['groups_base_dn'])
    groups_search_scope = FieldProperty(ILDAPPlugin['groups_search_scope'])
    group_prefix = FieldProperty(ILDAPPlugin['group_prefix'])
    group_uid_attribute = FieldProperty(ILDAPPlugin['group_uid_attribute'])
    group_title_format = FieldProperty(ILDAPPlugin['group_title_format'])
    group_members_query_mode = FieldProperty(ILDAPPlugin['group_members_query_mode'])
    groups_query = FieldProperty(ILDAPPlugin['groups_query'])
    group_members_attribute = FieldProperty(ILDAPPlugin['group_members_attribute'])
    user_groups_attribute = FieldProperty(ILDAPPlugin['user_groups_attribute'])
    group_mail_mode = FieldProperty(ILDAPPlugin['group_mail_mode'])
    group_replace_expression = FieldProperty(ILDAPPlugin['group_replace_expression'])
    group_mail_attribute = FieldProperty(ILDAPPlugin['group_mail_attribute'])
    group_extra_attributes = FieldProperty(ILDAPPlugin['group_extra_attributes'])

    users_select_query = FieldProperty(ILDAPPlugin['users_select_query'])
    users_search_query = FieldProperty(ILDAPPlugin['users_search_query'])
    groups_select_query = FieldProperty(ILDAPPlugin['groups_select_query'])
    groups_search_query = FieldProperty(ILDAPPlugin['groups_search_query'])

    @property
    def server_uri(self):
        return self._server_uri

    @server_uri.setter
    def server_uri(self, value):
        self._server_uri = value
        try:
            scheme, host = value.split('://', 1)
        except ValueError:
            scheme = 'ldap'
            host = value
        self._use_ssl = scheme == 'ldaps'
        self._scheme = scheme
        try:
            host, port = host.split(':', 1)
            port = int(port)
        except ValueError:
            port = 636 if self._use_ssl else 389
        self._host = host
        self._port = port

    @property
    def scheme(self):
        return self._scheme

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def use_ssl(self):
        return self._use_ssl

    def _get_id(self):
        intids = query_utility(IIntIds)
        return intids.register(self)

    def clear(self):
        self_id = self._get_id()
        if self_id in managers:
            del managers[self_id]

    def get_connection(self, user=None, password=None):
        self_id = self._get_id()
        if self_id not in managers:
            managers[self_id] = ConnectionManager(self)
        connection = managers[self_id].get_connection(user, password)
        if connection.closed:
            connection.open(read_server_info=False)
        return connection

    def authenticate(self, credentials, request):
        if not self.enabled:
            return None
        attrs = credentials.attributes
        login = attrs.get('login')
        password = attrs.get('password')
        conn = self.get_connection()
        search = LDAPQuery(self.base_dn, self.login_query, self.search_scope,
                           (self.login_attribute, self.uid_attribute))
        result = search.execute(conn, login=escape_filter_chars(login))
        if not result or len(result) > 1:
            return None
        result = result[0]
        login_dn = result[0]
        try:
            login_conn = self.get_connection(user=login_dn, password=password)
            login_conn.unbind()
        except LDAPBindError:
            LOGGER.debug("LDAP authentication exception with login %r", login, exc_info=True)
            return None
        else:
            if self.uid_attribute == 'dn':
                return "{prefix}:{dn}".format(prefix=self.prefix,
                                              dn=login_dn)
            attrs = result[1]
            if self.login_attribute in attrs:
                return "{prefix}:{attr}".format(prefix=self.prefix,
                                                attr=attrs[self.uid_attribute][0])
            return None

    def _get_group(self, group_id):
        if not self.enabled:
            return None

    def get_principal(self, principal_id, info=True):
        if not self.enabled:
            return None
        if not principal_id.startswith(self.prefix + ':'):
            return None
        prefix, login = principal_id.split(':', 1)
        conn = self.get_connection()
        if login.startswith(self.group_prefix + ':'):
            group_prefix, group_id = login.split(':', 1)
            attributes = FORMAT_ATTRIBUTES.findall(self.group_title_format) + \
                         [self.group_mail_attribute]
            if self.group_extra_attributes:
                attributes += self.group_extra_attributes.split(',')
            if self.group_uid_attribute == 'dn':
                search = LDAPQuery(group_id, '(objectClass=*)', BASE, attributes)
            else:
                search = LDAPQuery(self.base_dn, self.uid_query, self.search_scope, attributes)
            result = search.execute(conn, login=group_id)
            if not result or len(result) > 1:
                return None
            group_dn, attrs = result[0]
            if info:
                return PrincipalInfo(id='{prefix}:{group_prefix}:{group_id}'.format(
                    prefix=self.prefix,
                    group_prefix=self.group_prefix,
                    group_id=group_id),
                                     title=self.group_title_format.format(**attrs),
                                     dn=group_dn)
            else:
                attrs.update({'principal_id': '{prefix}:{group_prefix}:{group_id}'.format(
                    prefix=self.prefix,
                    group_prefix=self.group_prefix,
                    group_id=group_id)})
                return LDAPGroupInfo(group_dn, attrs, self)
        else:
            attributes = FORMAT_ATTRIBUTES.findall(self.title_format) + [self.mail_attribute]
            if self.user_extra_attributes:
                attributes += self.user_extra_attributes.split(',')
            if self.uid_attribute == 'dn':
                search = LDAPQuery(login, '(objectClass=*)', BASE, attributes)
            else:
                search = LDAPQuery(self.base_dn, self.uid_query, self.search_scope, attributes)
            result = search.execute(conn, login=login)
            if not result or len(result) > 1:
                return None
            user_dn, attrs = result[0]
            if info:
                return PrincipalInfo(id='{prefix}:{login}'.format(prefix=self.prefix,
                                                                  login=login),
                                     title=self.title_format.format(**attrs),
                                     dn=user_dn)
            attrs.update({'principal_id': '{prefix}:{login}'.format(
                prefix=self.prefix, login=login)})
            return LDAPUserInfo(user_dn, attrs, self)

    def _get_groups(self, principal):
        """Get principal groups"""
        principal_dn = principal.attributes.get('dn')
        if principal_dn is None:
            raise StopIteration
        if self.group_members_query_mode == 'group':
            # group members are defined inside group
            if not self.groups_base_dn:
                raise StopIteration
            conn = self.get_connection()
            attributes = FORMAT_ATTRIBUTES.findall(self.group_title_format)
            search = LDAPQuery(self.groups_base_dn, self.groups_query, self.groups_search_scope,
                               attributes)
            for group_dn, group_attrs in search.execute(conn, dn=principal_dn):
                if self.group_uid_attribute == 'dn':
                    yield '{prefix}:{group_prefix}:{dn}'.format(
                        prefix=self.prefix,
                        group_prefix=self.group_prefix,
                        dn=group_dn)
                else:
                    yield '{prefix}:{group_prefix}:{attr}'.format(
                        prefix=self.prefix,
                        group_prefix=self.group_prefix,
                        attr=group_attrs[self.group_uid_attribute])
        else:
            # a member defines it's groups
            conn = self.get_connection()
            attributes = [self.user_groups_attribute]
            user_search = LDAPQuery(principal_dn, '(objectClass=*)', BASE, attributes)
            for user_dn, user_attrs in user_search.execute(conn):
                if self.group_uid_attribute == 'dn':
                    for group_dn in user_attrs.get(self.user_groups_attribute, ()):
                        yield '{prefix}:{group_prefix}:{dn}'.format(
                            prefix=self.prefix,
                            group_prefix=self.group_prefix,
                            dn=group_dn)
                else:
                    attributes = [self.group_uid_attribute]
                    for group_dn in user_attrs.get(self.user_groups_attribute, ()):
                        group_search = LDAPQuery(group_dn, '(objectClass=*)', BASE,
                                                 attributes)
                        for group_search_dn, group_search_attrs in group_search.execute(conn):
                            yield '{prefix}:{group_prefix}:{attr}'.format(
                                prefix=self.prefix,
                                group_prefix=self.group_prefix,
                                attr=group_search_attrs[self.group_uid_attribute])

    @cache_region('short')
    def get_all_principals(self, principal_id):
        """Get all principals (including groups) for given principal ID"""
        if not self.enabled:
            return set()
        principal = self.get_principal(principal_id)
        if principal is not None:
            result = {principal_id}
            if self.groups_query:
                result |= set(self._get_groups(principal))
            return result
        return set()

    def get_members(self, group, info=True):
        """Get all members of given LDAP group as LDAP users"""
        if not self.enabled:
            return set()
        conn = self.get_connection()
        if self.group_members_query_mode == 'group':
            # group members are defined into group attribute
            attributes = [self.group_members_attribute]
            user_attributes = FORMAT_ATTRIBUTES.findall(self.title_format) + \
                              [self.mail_attribute]
            search = LDAPQuery(group.dn, '(objectClass=*)', BASE, attributes)
            for group_dn, attrs in search.execute(conn):
                for user_dn in attrs.get(self.group_members_attribute):
                    user_search = LDAPQuery(user_dn, '(objectClass=*)', BASE, user_attributes)
                    for user_search_dn, user_search_attrs in user_search.execute(conn):
                        if info:
                            yield PrincipalInfo(id='{prefix}:{dn}'.format(prefix=self.prefix,
                                                                          dn=user_search_dn),
                                                title=self.title_format.format(
                                                    **user_search_attrs),
                                                dn=user_search_dn)
                        else:
                            yield LDAPUserInfo(dn=user_search_dn, attributes=user_search_attrs,
                                               plugin=self)
        else:
            # member groups are defined into member attribute
            attributes = FORMAT_ATTRIBUTES.findall(self.title_format) + \
                         [self.uid_attribute, self.mail_attribute]
            search = LDAPQuery(self.base_dn, '({attribute}={{group_dn}})'.format(
                attribute=self.user_groups_attribute),
                               self.search_scope, attributes)
            for user_dn, user_attrs in search.execute(conn, group_dn=group.dn):
                if info:
                    if self.uid_attribute == 'dn':
                        yield PrincipalInfo(id='{prefix}:{dn}'.format(
                            prefix=self.prefix,
                            dn=user_dn),
                                            title=self.title_format.format(**user_attrs),
                                            dn=user_dn)
                    else:
                        yield PrincipalInfo(id='{prefix}:{attr}'.format(
                            prefix=self.prefix,
                            attr=user_attrs[self.uid_attribute][0]),
                                            title=self.title_format.format(**user_attrs),
                                            dn=user_dn)
                else:
                    yield LDAPUserInfo(dn=user_dn, attributes=user_attrs, plugin=self)

    def find_principals(self, query):
        if not self.enabled:
            raise StopIteration
        if not query:
            return None
        conn = self.get_connection()
        # users search
        attributes = FORMAT_ATTRIBUTES.findall(self.title_format) + [self.uid_attribute, ]
        search = LDAPQuery(self.base_dn, self.users_select_query,
                           self.search_scope, attributes)
        for user_dn, user_attrs in search.execute(conn, query=query):
            if self.uid_attribute == 'dn':
                yield PrincipalInfo(id='{prefix}:{dn}'.format(prefix=self.prefix,
                                                              dn=user_dn),
                                    title=self.title_format.format(**user_attrs),
                                    dn=user_dn)
            else:
                yield PrincipalInfo(id='{prefix}:{attr}'.format(
                    prefix=self.prefix,
                    attr=user_attrs[self.uid_attribute][0]),
                                    title=self.title_format.format(**user_attrs),
                                    dn=user_dn)
        # groups search
        if self.groups_base_dn:
            attributes = FORMAT_ATTRIBUTES.findall(self.group_title_format) + \
                         [self.group_uid_attribute, ]
            search = LDAPQuery(self.groups_base_dn, self.groups_select_query,
                               self.groups_search_scope, attributes)
            for group_dn, group_attrs in search.execute(conn, query=query):
                if self.group_uid_attribute == 'dn':
                    yield PrincipalInfo(id='{prefix}:{group_prefix}:{dn}'.format(
                        prefix=self.prefix,
                        group_prefix=self.group_prefix,
                        dn=group_dn),
                                        title=self.group_title_format.format(**group_attrs),
                                        dn=group_dn)
                else:
                    yield PrincipalInfo(id='{prefix}:{group_prefix}:{attr}'.format(
                        prefix=self.prefix,
                        group_prefix=self.group_prefix,
                        attr=group_attrs[self.group_uid_attribute][0]),
                                        title=self.group_title_format.format(**group_attrs),
                                        dn=group_dn)

    def get_search_results(self, data):
        # LDAP search results are made of tuples containing DN and all
        # entries attributes
        query = data.get('query')
        if not query:
            return ()
        conn = self.get_connection()
        # users search
        search = LDAPQuery(self.base_dn, self.users_search_query,
                           self.search_scope, ALL_ATTRIBUTES)
        for user_dn, user_attrs in search.execute(conn, query=query):
            yield user_dn, user_attrs
        # groups search
        if self.groups_base_dn:
            search = LDAPQuery(self.groups_base_dn, self.groups_search_query,
                               self.groups_search_scope, ALL_ATTRIBUTES)
            for group_dn, group_attrs in search.execute(conn, query=query):
                yield group_dn, group_attrs
