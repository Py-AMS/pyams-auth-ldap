=================================
PyAMS LDAP authentication package
=================================

.. contents::


What is PyAMS?
==============

PyAMS (Pyramid Application Management Suite) is a small suite of packages written for applications
and content management with the Pyramid framework.

**PyAMS** is actually mainly used to manage web sites through content management applications (CMS,
see PyAMS_content package), but many features are generic and can be used inside any kind of web
application.

All PyAMS documentation is available on `ReadTheDocs <https://pyams.readthedocs.io>`_; source code
is available on `Gitlab <https://gitlab.com/pyams>`_ and pushed to `Github
<https://github.com/py-ams>`_. Doctests are available in the *doctests* source folder.


What is PyAMS LDAP authentication package?
==========================================

PyAMS LDAP authentication package is an extension package for PyAMS_security, which allows
users authentication from an LDAP directory.

This plug-in also supports LDAP groups, to be able to set groups as principals to grant roles.
