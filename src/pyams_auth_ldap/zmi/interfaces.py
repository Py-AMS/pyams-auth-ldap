#
# Copyright (c) 2015-2022 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_auth_ldap.zmi.interfaces module

This module defines marker interfaces which are used to define LDAP plug-in subforms.
"""

from zope.interface import Interface


__docformat__ = 'restructuredtext'


class ILDAPPluginConnectionSubform(Interface):
    """LDAP plugin connection subform marker interface"""


class ILDAPPluginUsersSchemaSubform(Interface):
    """LDAP plugin users schema subform marker interface"""


class ILDAPPluginGroupsSchemaSubform(Interface):
    """LDAP plugin groups schema subform marker interface"""


class ILDAPPluginSearchSettingsSubform(Interface):
    """LDAP plugin search schema subform marker interface"""
