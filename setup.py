#!/usr/bin/env python3

import sys
import setuptools


if not sys.platform.startswith('win'):
    data_files = [
        ('share/man/man1', ['man/hashsum.1']),
    ]
else:
    data_files = None


setuptools.setup(data_files=data_files)
