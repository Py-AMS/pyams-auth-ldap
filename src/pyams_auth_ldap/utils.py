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

"""PyAMS_auth_ldap.utils module

This module defines a small set of utility functions.
"""

__docformat__ = 'restructuredtext'


def get_single_value(entry):
    """Get single value for provided input"""
    if isinstance(entry, (list, tuple)):
        return '<br />'.join(map(get_single_value, entry))
    if isinstance(entry, bytes):
        return entry.decode('utf-8', 'ignore')
    return str(entry)


def get_dict_values(entries: dict, attributes: list):
    """Get given attributes from entries"""
    values = {}
    for attr in attributes:
        values[attr] = get_single_value(entries[attr])
    return values


def get_formatted_value(formatter: str, **entries: dict):
    """Get formatted value of given formatter with provided entries"""
    for key, value in entries.items():
        entries[key] = get_single_value(value)
    return formatter.format(**entries)
