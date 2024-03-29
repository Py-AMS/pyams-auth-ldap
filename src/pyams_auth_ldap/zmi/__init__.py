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

"""PyAMS_auth_ldap.zmi module

This module defines view and content providers used to manage LDAP directory plug-ins.
"""

import base64

from ldap3 import ALL_ATTRIBUTES, BASE
from pyramid.decorator import reify
from zope.interface import Interface, implementer

from pyams_auth_ldap.interfaces import ILDAPPlugin, LDAP_PLUGIN_LABEL
from pyams_auth_ldap.query import LDAPQuery
from pyams_auth_ldap.utils import get_single_value
from pyams_auth_ldap.zmi.interfaces import ILDAPPluginConnectionSubform, \
    ILDAPPluginGroupsSchemaSubform, ILDAPPluginSearchSettingsSubform, \
    ILDAPPluginUsersSchemaSubform
from pyams_form.ajax import ajax_form_config
from pyams_form.browser.checkbox import SingleCheckBoxFieldWidget
from pyams_form.field import Fields
from pyams_form.interfaces.form import IFormFields, IInnerTabForm
from pyams_form.subform import InnerAddForm, InnerEditForm
from pyams_layer.interfaces import IPyAMSLayer
from pyams_pagelet.pagelet import pagelet_config
from pyams_security.interfaces import IPlugin, ISecurityManager
from pyams_security.interfaces.base import MANAGE_SECURITY_PERMISSION
from pyams_security_views.zmi import SecurityPluginsTable
from pyams_security_views.zmi.plugin import SecurityPluginAddForm, \
    SecurityPluginAddMenu, SecurityPluginPropertiesEditForm
from pyams_skin.interfaces.viewlet import IContentSuffixViewletManager
from pyams_table.column import GetAttrColumn
from pyams_table.interfaces import IColumn, IValues
from pyams_utils.adapter import ContextRequestViewAdapter, adapter_config
from pyams_utils.registry import get_utility
from pyams_utils.url import absolute_url
from pyams_viewlet.viewlet import viewlet_config
from pyams_zmi.form import AdminModalDisplayForm
from pyams_zmi.interfaces import IAdminLayer, TITLE_SPAN_BREAK
from pyams_zmi.interfaces.form import IFormTitle
from pyams_zmi.interfaces.table import IInnerTable
from pyams_zmi.interfaces.viewlet import IContextAddingsViewletManager
from pyams_zmi.search import SearchForm, SearchResultsView, SearchView
from pyams_zmi.table import I18nColumnMixin, Table
from pyams_zmi.utils import get_object_label


__docformat__ = 'restructuredtext'

from pyams_auth_ldap import _  # pylint: disable=ungrouped-imports


#
# LDAP plug-in add form
#


@viewlet_config(name='add-ldap-plugin.menu',
                context=ISecurityManager, layer=IAdminLayer, view=SecurityPluginsTable,
                manager=IContextAddingsViewletManager, weight=40,
                permission=MANAGE_SECURITY_PERMISSION)
class LDAPPluginAddMenu(SecurityPluginAddMenu):
    """LDAP plug-in add menu"""

    label = _("Add LDAP directory...")
    href = 'add-ldap-plugin.html'


@ajax_form_config(name='add-ldap-plugin.html',
                  context=ISecurityManager, layer=IPyAMSLayer,
                  permission=MANAGE_SECURITY_PERMISSION)
class LDAPPluginAddForm(SecurityPluginAddForm):
    """LDAP plug-in add form"""

    content_factory = ILDAPPlugin
    content_label = LDAP_PLUGIN_LABEL

    fields = Fields(IPlugin).omit('__parent__', '__name__')
    fields['enabled'].widget_factory = SingleCheckBoxFieldWidget


@adapter_config(name='connection',
                required=(ISecurityManager, IAdminLayer, LDAPPluginAddForm),
                provides=IInnerTabForm)
@implementer(ILDAPPluginConnectionSubform)
class LDAPPluginConnectionAddForm(InnerAddForm):
    """LDAP plug-in add form connection sub-form"""

    title = _("Connection")

    weight = 1


@adapter_config(name='users-schema',
                required=(ISecurityManager, IAdminLayer, LDAPPluginAddForm),
                provides=IInnerTabForm)
class LDAPPluginUsersSchemaAddForm(InnerAddForm):
    """LDAP plug-in add form users schema properties sub-form"""

    title = _("Users schema")

    fields = Fields(ILDAPPlugin).select('base_dn', 'search_scope', 'login_attribute',
                                        'login_query', 'uid_attribute', 'uid_query',
                                        'title_format', 'mail_attribute',
                                        'user_extra_attributes')
    weight = 10


@adapter_config(name='groups-schema',
                required=(ISecurityManager, IAdminLayer, LDAPPluginAddForm),
                provides=IInnerTabForm)
class LDAPPluginGroupsSchemaAddForm(InnerAddForm):
    """LDAP plug-in add form groups schema properties sub-form"""

    title = _("Groups schema")

    fields = Fields(ILDAPPlugin).select('groups_base_dn', 'groups_search_scope', 'group_prefix',
                                        'group_uid_attribute', 'group_title_format',
                                        'group_members_query_mode', 'groups_query',
                                        'group_members_attribute', 'user_groups_attribute',
                                        'group_mail_mode', 'group_replace_expression',
                                        'group_mail_attribute', 'group_extra_attributes')
    weight = 20


@adapter_config(name='search-settings',
                required=(ISecurityManager, IAdminLayer, LDAPPluginAddForm),
                provides=IInnerTabForm)
class LDAPPluginSearchSettingsAddForm(InnerAddForm):
    """LDAP plug-in add form search settings sub-form"""

    title = _("Search settings")

    fields = Fields(ILDAPPlugin).select('users_select_query', 'users_search_query',
                                        'groups_select_query', 'groups_search_query')
    weight = 30


#
# LDAP plug-in properties edit form
#

@ajax_form_config(name='properties.html', context=ILDAPPlugin, layer=IPyAMSLayer)
class LDAPPluginPropertiesEditForm(SecurityPluginPropertiesEditForm):
    """LDAP plug-in properties edit form"""


@adapter_config(name='connection',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginPropertiesEditForm),
                provides=IInnerTabForm)
@implementer(ILDAPPluginConnectionSubform)
class LDAPPluginConnectionEditForm(InnerEditForm):
    """LDAP plug-in connection edit form"""

    title = _("Connection")

    weight = 1


@adapter_config(name='users-schema',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginPropertiesEditForm),
                provides=IInnerTabForm)
class LDAPPluginUsersSchemaEditForm(InnerEditForm):
    """LDAP plug-in users schema properties edit form"""

    title = _("Users schema")

    fields = Fields(ILDAPPlugin).select('base_dn', 'search_scope', 'login_attribute',
                                        'login_query', 'uid_attribute', 'uid_query',
                                        'title_format', 'mail_attribute',
                                        'user_extra_attributes')
    weight = 10


@adapter_config(name='groups-schema',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginPropertiesEditForm),
                provides=IInnerTabForm)
class LDAPPluginGroupsSchemaEditForm(InnerEditForm):
    """LDAP plug-in groups schema properties edit form"""

    title = _("Groups schema")

    fields = Fields(ILDAPPlugin).select('groups_base_dn', 'groups_search_scope', 'group_prefix',
                                        'group_uid_attribute', 'group_title_format',
                                        'group_members_query_mode', 'groups_query',
                                        'group_members_attribute', 'user_groups_attribute',
                                        'group_mail_mode', 'group_replace_expression',
                                        'group_mail_attribute', 'group_extra_attributes')
    weight = 20


@adapter_config(name='search-settings',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginPropertiesEditForm),
                provides=IInnerTabForm)
class LDAPPluginSearchSettingsEditForm(InnerEditForm):
    """LDAP plug-in search settings edit form"""

    title = _("Search settings")

    fields = Fields(ILDAPPlugin).select('users_select_query', 'users_search_query',
                                        'groups_select_query', 'groups_search_query')
    weight = 30


#
# LDAP plug-in sub-forms fields adapters
#

@adapter_config(required=(Interface, IAdminLayer, ILDAPPluginConnectionSubform),
                provides=IFormFields)
def ldap_plugin_connection_fields(context, request, view):  # pylint: disable=unused-argument
    """LDAP plugin connection fields"""
    return Fields(ILDAPPlugin).select('server_uri', 'start_tls',
                                      'bind_dn', 'bind_password', 'bind_mode')


@adapter_config(required=(Interface, IAdminLayer, ILDAPPluginUsersSchemaSubform),
                provides=IFormFields)
def ldap_plugin_users_schema_fields(context, request, view):  # pylint: disable=unused-argument
    """LDAP plugin users schema fields"""
    return Fields(ILDAPPlugin).select('base_dn', 'search_scope', 'login_attribute',
                                      'login_query', 'uid_attribute', 'uid_query',
                                      'title_format', 'mail_attribute',
                                      'user_extra_attributes')


@adapter_config(required=(Interface, IAdminLayer, ILDAPPluginGroupsSchemaSubform),
                provides=IFormFields)
def ldap_plugin_groups_schema_fields(context, request, view):  # pylint: disable=unused-argument
    """LDAP plugin groups schema fields"""
    return Fields(ILDAPPlugin).select('groups_base_dn', 'groups_search_scope', 'group_prefix',
                                      'group_uid_attribute', 'group_title_format',
                                      'group_members_query_mode', 'groups_query',
                                      'group_members_attribute', 'user_groups_attribute',
                                      'group_mail_mode', 'group_replace_expression',
                                      'group_mail_attribute', 'group_extra_attributes')


@adapter_config(required=(Interface, IAdminLayer, ILDAPPluginSearchSettingsSubform),
                provides=IFormFields)
def ldap_plugin_search_settings_fields(context, request, view):  # pylint: disable=unused-argument
    """LDAP plugin search settings fields"""
    return Fields(ILDAPPlugin).select('users_select_query', 'users_search_query',
                                      'groups_select_query', 'groups_search_query')

#
# LDAP folder search view
#

class LDAPPluginSearchForm(SearchForm):  # pylint: disable=abstract-method
    """LDAP plug-in search form"""

    title = _("LDAP directory search form")

    @property
    def back_url(self):
        """Form back URL getter"""
        manager = get_utility(ISecurityManager)
        return absolute_url(manager, self.request, 'security-plugins.html')


@pagelet_config(name='search.html', context=ILDAPPlugin, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION)
class LDAPPluginSearchView(SearchView):
    """LDAP plug-in search view"""

    title = _("LDAP directory search form")
    search_form = LDAPPluginSearchForm


class LDAPPluginSearchResultsTable(Table):
    """LDAP plug-in search results table"""

    @reify
    def data_attributes(self):
        attributes = super().data_attributes
        attributes.setdefault('tr', {}).update({
            'data-ams-url': lambda row, col: absolute_url(self.context, self.request,
                                                          'ldap-properties.html',
                                                          query={'dn': row[0]}),
            'data-toggle': 'modal'
        })
        return attributes

    batch_size = 999


@adapter_config(required=(ILDAPPlugin, IAdminLayer, LDAPPluginSearchResultsTable),
                provides=IValues)
class LDAPPluginSearchResultsValues(ContextRequestViewAdapter):
    """LDAP plug-in search results values"""

    @property
    def values(self):
        """LDAP plug-in search table results getter"""
        yield from self.context.get_search_results({
            'query': self.request.params.get('form.widgets.query')
        })


class LDAPColumn(I18nColumnMixin, GetAttrColumn):
    """Base LDAP column"""

    def get_value(self, obj):
        value = obj[1].get(self.attr_name, ())
        return '<br /> '.join(value) if isinstance(value, (list, tuple)) else value


@adapter_config(name='uid',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginSearchResultsTable),
                provides=IColumn)
class LDAPPluginSearchUIDColumn(LDAPColumn):
    """LDAP plug-in search UID column"""

    i18n_header = _("UID")

    @property
    def attr_name(self):
        return self.context.uid_attribute

    weight = 10


@adapter_config(name='cn',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginSearchResultsTable),
                provides=IColumn)
class LDAPPluginSearchCNColumn(LDAPColumn):
    """LDAP plug-in search CN column"""

    i18n_header = _("Common name")
    attr_name = 'cn'

    weight = 20


@adapter_config(name='mail',
                required=(ILDAPPlugin, IAdminLayer, LDAPPluginSearchResultsTable),
                provides=IColumn)
class LDAPPluginSearchMailColumn(LDAPColumn):
    """LDAP plug-in search mail column"""

    i18n_header = _("Mail address")
    attr_name = 'mail'

    weight = 30


@pagelet_config(name='search-results.html', context=ILDAPPlugin, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION, xhr=True)
class LDAPPluginSearchResultsView(SearchResultsView):
    """LDAP plug-in search results view"""

    table_label = _("Search results")
    table_class = LDAPPluginSearchResultsTable


#
# LDAP entry display view
#

@pagelet_config(name='ldap-properties.html',
                context=ILDAPPlugin, layer=IPyAMSLayer,
                permission=MANAGE_SECURITY_PERMISSION)
class LDAPEntryPropertiesDisplayForm(AdminModalDisplayForm):
    """LDAP entry properties display form"""

    modal_class = 'modal-xl'

    legend = _("LDAP entry attributes")
    fields = Fields(Interface)

    @reify
    def ldap_entry(self):
        """LDAP entry getter"""
        plugin = self.context
        conn = plugin.get_connection()
        dn = self.request.params.get('dn')  # pylint: disable=invalid-name
        query = LDAPQuery(dn, '(objectclass=*)', BASE, ALL_ATTRIBUTES)
        result = query.execute(conn)
        if not result or len(result) > 1:
            return {}
        dn, attributes = result[0]  # pylint: disable=invalid-name
        photo = attributes.get('jpegPhoto')
        if photo is not None:
            if isinstance(photo, list):
                photo = photo[0]
            attributes['jpegPhoto'] = [
                '<img src="data:image/jpeg;base64,{0}" />'.format(
                    base64.encodebytes(photo).decode())
            ]
        photo = attributes.get('thumbnailPhoto')
        if photo is not None:
            if isinstance(photo, list):
                photo = photo[0]
            attributes['thumbnailPhoto'] = [
                '<img src="data:image/jpeg;base64,{0}" />'.format(
                    base64.encodebytes(photo).decode())
            ]
        result = sorted(attributes.items(), key=lambda x: x[0])
        return {
            'dn': dn,
            'attributes': result
        }


@adapter_config(required=(ILDAPPlugin, IAdminLayer, LDAPEntryPropertiesDisplayForm),
                provides=IFormTitle)
def ldap_entry_display_form_title(context, request, form):
    """LDAP entry display form title getter"""
    translate = request.localizer.translate
    return TITLE_SPAN_BREAK.format(
        get_object_label(context, request, form),
        translate(_("DN: {}")).format(form.ldap_entry.get('dn', _('unknown'))))


@viewlet_config(name='entry-properties',
                context=ILDAPPlugin, layer=IAdminLayer,
                view=LDAPEntryPropertiesDisplayForm,
                manager=IContentSuffixViewletManager)
@implementer(IInnerTable)
class LDAPEntryPropertiesTable(Table):
    """LDAP entry properties table"""

    def __init__(self, context, request, view, manager):
        super().__init__(context, request)
        self.view = view
        self.manager = manager

    batch_size = 999


@adapter_config(required=(ILDAPPlugin, IAdminLayer, LDAPEntryPropertiesTable),
                provides=IValues)
class LDAPEntryPropertiesTableValues(ContextRequestViewAdapter):
    """LDAP entry properties table values"""

    @property
    def values(self):
        """LDAP entry attributes getter"""
        yield from self.view.view.ldap_entry.get('attributes', ())


@adapter_config(name='attribute',
                required=(ILDAPPlugin, IAdminLayer, LDAPEntryPropertiesTable),
                provides=IColumn)
class LDAPEntryAttributeColumn(I18nColumnMixin, GetAttrColumn):
    """LDAP entry attribute column"""

    i18n_header = _("Attribute")
    weight = 10

    def get_value(self, obj):
        return obj[0]


@adapter_config(name='values',
                required=(ILDAPPlugin, IAdminLayer, LDAPEntryPropertiesTable),
                provides=IColumn)
class LDAPEntryValuesColumn(I18nColumnMixin, GetAttrColumn):
    """LDAP entry values column"""

    i18n_header = _("Value")
    weight = 20

    def get_value(self, obj):
        """Value getter"""
        return get_single_value(obj[1])
