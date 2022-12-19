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

"""PyAMS_auth_ldap.query module

This module provides a simple wrapper to handle LDAP queries.

"""

import logging


__docformat__ = 'restructuredtext'

LOGGER = logging.getLogger('PyAMS (ldap)')


class LDAPQuery:
    """Object representing an LDAP query"""

    def __init__(self, base_dn, filter_tmpl, scope, attributes):
        self.base_dn = base_dn.strip()
        self.filter_tmpl = filter_tmpl
        self.scope = scope
        self.attributes = attributes

    def __str__(self):
        return ('base_dn={base_dn}, filter_tmpl={filter_tmpl}, '
                'scope={scope}, attributes={attributes}'.format(**self.__dict__))

    def execute(self, conn, **kwargs):
        """Execute an LDAP query"""
        key = (self.base_dn.format(**kwargs), self.filter_tmpl.format(**kwargs))
        LOGGER.debug(f">>> LDAP query: {self.filter_tmpl} (base {self.base_dn})")
        LOGGER.debug(f"  >      args: {kwargs}")
        ret = conn.search(search_scope=self.scope,
                          attributes=self.attributes,
                          *key)
        result, status, request = conn.get_response(ret, get_request=True)
        LOGGER.debug(f"  > LDAP request: {request}")
        LOGGER.debug(f"  < LDAP status: {status}")
        if result is None:
            result = []
        else:
            result = [
                (r['dn'], r['attributes'])
                for r in result
                if 'dn' in r
            ]
        LOGGER.debug(f"<<< LDAP result: {result}")
        return result
