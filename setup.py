#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# 2020-2021 DVRPC

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages

version = "0.8.0"

setup(
    name="ckanext-oauth2",
    version=version,
    description="Oauth for CKAN",
    long_descrition="""
    The OAuth2 extension allows site visitors to login through an OAuth2 server.
    """,
    keywords="CKAN, OAuth2",
    author="Aitor Magán, Kris Warner",
    author_email="amagan@conwet.com, kdwarn@protonmail.com",
    url="https://github.com/dvrpc/ckanext-oauth2",
    license="MIT",
    packages=find_packages(exclude=["ez_setup", "examples", "tests"]),
    namespace_packages=["ckanext"],
    include_package_data=True,
    zip_safe=False,
    setup_requires=["nose>=1.3.0"],
    install_requires=[
        "requests-oauthlib==0.8.0",
        "pyjwt==1.7.1",
    ],
    entry_points="""
        [ckan.plugins]
        oauth2=ckanext.oauth2.plugin:OAuth2Plugin
    """,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
)
