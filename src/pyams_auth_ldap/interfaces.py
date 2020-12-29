#
# Copyright (c) 2015-2019 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_auth_ldap.interfaces module

"""

import re

from ldap3 import BASE, LEVEL, SUBTREE
from zope.interface import Attribute, Interface
from zope.schema import Choice, TextLine
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from pyams_security.interfaces import IAuthenticationPlugin, IDirectorySearchPlugin

from pyams_auth_ldap import _


#
# Search scopes vocabulary
#


SEARCH_SCOPES = {
    BASE: _("Base object"),
    LEVEL: _("Single level"),
    SUBTREE: _("Whole subtree")
}

SEARCH_SCOPES_VOCABULARY = SimpleVocabulary([
    SimpleTerm(v, title=t) for v, t in SEARCH_SCOPES.items()
])


#
# Group members query mode
#

QUERY_MEMBERS_FROM_GROUP = 'group'
QUERY_MEMBERS_FROM_MEMBER = 'member'

GROUP_MEMBERS_QUERY_MODE = {
    QUERY_MEMBERS_FROM_GROUP: _("Use group attribute to get members list"),
    QUERY_MEMBERS_FROM_MEMBER: _("Use member attribute to get groups list")
}

GROUP_MEMBERS_QUERY_MODE_VOCABULARY = SimpleVocabulary([
    SimpleTerm(v, title=t) for v, t in GROUP_MEMBERS_QUERY_MODE.items()
])


#
# Group mail mode
#

NO_GROUP_MAIL_MODE = 'none'
INTERNAL_GROUP_MAIL_MODE = 'internal'
REDIRECT_GROUP_MAIL_MODE = 'redirect'

GROUP_MAIL_MODE = {
    NO_GROUP_MAIL_MODE: _("none (only use members own mail address)"),
    INTERNAL_GROUP_MAIL_MODE: _("Use group internal attribute"),
    REDIRECT_GROUP_MAIL_MODE: _("Use another group internal attribute")
}

GROUP_MAIL_MODE_VOCABULARY = SimpleVocabulary([
    SimpleTerm(v, title=t) for v, t in GROUP_MAIL_MODE.items()
])


class ILDAPBaseInfo(Interface):
    """LDAP base entry interface"""

    dn = Attribute("LDAP DN")

    attributes = Attribute("Entry attributes")


class ILDAPUserInfo(ILDAPBaseInfo):
    """LDAP user entry interface"""


class ILDAPGroupInfo(ILDAPBaseInfo):
    """LDAP group entry interface"""

    def get_members(self):
        """Get all group members"""


DEFAULT_UID_QUERY = '(uid={login})'
DEFAULT_USER_SEARCH = '(|(givenName={query}*)(sn={query}*))'
DEFAULT_GROUP_SEARCH = '(cn=*{query}*)'


class ILDAPPlugin(IAuthenticationPlugin, IDirectorySearchPlugin):
    """LDAP authentication plug-in interface"""

    server_uri = TextLine(title=_("LDAP server URI"),
                          description=_("Full URI (including protocol) of LDAP server"),
                          default="ldap://localhost:389",
                          required=True)

    bind_dn = TextLine(title=_("Bind DN"),
                       description=_("DN used for LDAP bind; keep empty for anonymous"),
                       required=False)

    bind_password = TextLine(title=_("Bind password"),
                             description=_("Password used for LDAP bind"),
                             required=False)

    base_dn = TextLine(title=_("Base DN"),
                       description=_("LDAP base DN"),
                       required=True)

    search_scope = Choice(title=_("Search scope"),
                          vocabulary=SEARCH_SCOPES_VOCABULARY,
                          default=SUBTREE,
                          required=True)

    login_attribute = TextLine(title=_("Login attribute"),
                               description=_("LDAP attribute used as user login"),
                               required=True,
                               default='uid')

    login_query = TextLine(title=_("Login query"),
                           description=_("Query template used to authenticate user "
                                         "(you can replace login attribute with '{login}')"),
                           required=True,
                           default=DEFAULT_UID_QUERY)

    uid_attribute = TextLine(title=_("UID attribute"),
                             description=_("LDAP attribute used as principal identifier"),
                             required=True,
                             default='dn')

    uid_query = TextLine(title=_("UID query"),
                         description=_("Query template used to get principal information "
                                       "(you can replace UID attribute with '{login}')"),
                         required=True,
                         default=DEFAULT_UID_QUERY)

    title_format = TextLine(title=_("Title format"),
                            description=_("Principal's title format string"),
                            required=True,
                            default='{givenName[0]} {sn[0]}')

    mail_attribute = TextLine(title=_("Mail attribute"),
                              description=_("LDAP attribute storing mail address"),
                              required=True,
                              default='mail')

    user_extra_attributes = TextLine(title=_("Extra attributes"),
                                     description=_("Comma separated list of additional "
                                                   "attributes which will be extracted by "
                                                   "principals"),
                                     required=False)

    groups_base_dn = TextLine(title=_("Groups base DN"),
                              description=_("Base DN used to search LDAP groups; keep empty to "
                                            "disable groups usage"),
                              required=False)

    groups_search_scope = Choice(title=_("Groups search scope"),
                                 vocabulary=SEARCH_SCOPES_VOCABULARY,
                                 default=SUBTREE,
                                 required=False)

    group_prefix = TextLine(title=_("Group prefix"),
                            description=_("Prefix used to identify groups as principals"),
                            required=False,
                            default='group')

    group_uid_attribute = TextLine(title=_("Group UID attribute"),
                                   description=_("LDAP attribute used as group identifier"),
                                   required=False,
                                   default='dn')

    group_title_format = TextLine(title=_("Group title format"),
                                  description=_("Principal's title format string"),
                                  required=True,
                                  default='{cn[0]}')

    group_members_query_mode = Choice(title=_("Members query mode"),
                                      description=_("Define how groups members are defined"),
                                      vocabulary=GROUP_MEMBERS_QUERY_MODE_VOCABULARY,
                                      default='group')

    groups_query = TextLine(title=_("Groups query"),
                            description=_("When members are stored inside a group attribute, "
                                          "this query template is used to get principal groups "
                                          "(based on DN and UID attributes called '{dn}' "
                                          "and '{login}')"),
                            required=False,
                            default="(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))")

    group_members_attribute = TextLine(title=_("Group members attribute"),
                                       description=_("When groups members are stored inside a "
                                                     "group attribute, this is the attribute "
                                                     "name"),
                                       required=False,
                                       default='uniqueMember')

    user_groups_attribute = TextLine(title=_("User groups attribute"),
                                     description=_("When user groups are stored inside a user "
                                                   "attribute, this is the attribute name"),
                                     required=False,
                                     default='memberOf')

    group_mail_mode = Choice(title=_("Group mail mode"),
                             description=_("Define how an email can be sent to group members"),
                             vocabulary=GROUP_MAIL_MODE_VOCABULARY,
                             required=True,
                             default='none')

    group_replace_expression = TextLine(title=_("DN replace expression"),
                                        description=_("In 'redirect' mail mode, specify source "
                                                      "and target DN parts, separated by a pipe"),
                                        constraint=re.compile(
                                            "[a-zA-Z0-9-=,]+|[a-zA-Z0-9-=,]+").match,
                                        default='ou=access|ou=lists')

    group_mail_attribute = TextLine(title=_("Mail attribute"),
                                    description=_("In 'internal' mail mode, specify name of "
                                                  "group mail attribute"),
                                    required=True,
                                    default='mail')

    group_extra_attributes = TextLine(title=_("Extra attributes"),
                                      description=_("Comma separated list of additional "
                                                    "attributes which will be extracted by "
                                                    "groups principals"),
                                      required=False)

    users_select_query = TextLine(title=_("Users select query"),
                                  description=_("Query template used to select users"),
                                  required=True,
                                  default=DEFAULT_USER_SEARCH)

    users_search_query = TextLine(title=_("Users search query"),
                                  description=_("Query template used to search users"),
                                  required=True,
                                  default=DEFAULT_USER_SEARCH)

    groups_select_query = TextLine(title=_("Groups select query"),
                                   description=_("Query template used to select groups"),
                                   required=True,
                                   default=DEFAULT_GROUP_SEARCH)

    groups_search_query = TextLine(title=_("Groups search query"),
                                   description=_("Query template used to search groups"),
                                   required=True,
                                   default=DEFAULT_GROUP_SEARCH)

    def get_connection(self):
        """Get LDAP connection"""
