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
        '^VERSION\s*=\s*(?P<quote>[\'"])(?P<version>[^\'"]+)(?P=quote)',
        data,
        re.MULTILINE)
    return mobj.group('version')


install_requires = ['enum34'] if sys.version_info[:2] < (3, 4) else []
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Operating System :: OS Independent',
    ],
    keywords='checksum hash',
    py_modules=['hashsum'],
    install_requires=install_requires,
    # extras_require={},
    # package_data={},
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'hashsum=hashsum:main',
        ],
    },
    test_suite='tests',
)
