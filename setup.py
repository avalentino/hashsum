#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
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


setup(
    name='hashsum',
    version=get_version(),
    description='Python drop-in replacement for md5sum and co.',
    # long_description='',
    url='https://github.com/avalentino/hashsum',
    author='Antonio Valentino',
    author_email='antonio.valentino@tiscli.it',
    license='BSD',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Utilities',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='checksum hash',
    py_modules=['hashsum'],
    # install_requires=[],
    # extras_require={},
    # package_data={},
    # data_files=[],
    entry_points={
        'console_scripts': [
            'hashsum=hashsum:main',
        ],
    },
)
