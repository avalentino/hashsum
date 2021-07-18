#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
from setuptools import setup


def get_version():
    filename = os.path.join(os.path.dirname(__file__), 'hashsum.py')
    with open(filename) as fd:
        data = fd.read()
    mobj = re.search(
        r'^__version__\s*=\s*(?P<quote>[\'"])(?P<version>[^\'"]+)(?P=quote)',
        data,
        re.MULTILINE)
    return mobj.group('version')


if not sys.platform.startswith('win'):
    data_files = [
        ('share/man/man1', ['man/hashsum.1']),
    ]
else:
    data_files = None


setup(
    name='hashsum',
    version=get_version(),
    description='Python drop-in replacement for md5sum and co.',
    # long_description='',
    url='https://github.com/avalentino/hashsum',
    download_url='https://pypi.python.org/pypi/hashsum',
    author='Antonio Valentino',
    author_email='antonio.valentino@tiscli.it',
    license='BSD',
    platforms=['any'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Utilities',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Operating System :: OS Independent',
    ],
    keywords='checksum hash',
    py_modules=['hashsum'],
    extras_require={
        'cli_autocomplete': ['aurgcomplete']
    },
    # package_data={},
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'hashsum=hashsum:main',
        ],
    },
)
