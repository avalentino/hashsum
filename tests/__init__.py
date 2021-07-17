import os
import sys
import locale
import platform
import unittest

import hashsum


def print_versions():
    print('hashsum version:      %s' % hashsum.__version__)

    print('Python version:       %s' % platform.python_version())
    print('Platform:             %s' % platform.platform())
    print('Byte-ordering:        %s' % sys.byteorder)
    print('Default encoding:     %s' % sys.getdefaultencoding())
    print('Default FS encoding:  %s' % sys.getfilesystemencoding())
    print('Default locale:       (%s, %s)' % locale.getdefaultlocale())

    print()

    sys.stdout.flush()


def suite():
    modules = [
        'test_hashsum',
    ]

    loader = unittest.TestLoader()
    alltests = unittest.TestSuite()
    for module in modules:
        if isinstance(module, str):
            module = __import__('tests.' + module, fromlist=('tests',))

        suite_ = loader.loadTestsFromModule(module)
        alltests.addTest(suite_)

    return alltests


def test(verbosity=1, failfast=False):
    print_versions()
    runner = unittest.TextTestRunner(verbosity=verbosity, failfast=failfast)
    result = runner.run(suite())

    return os.EX_OK if result.wasSuccessful() else 1
