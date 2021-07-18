#!/usr/bin/env python3


import os
import sys
import locale
import logging
import platform
import unittest
import warnings
import contextlib
from io import StringIO

import hashsum


TESTDIRPATH = os.path.abspath(os.path.dirname(__file__))
DATAPATH = os.path.join(TESTDIRPATH, 'data')

MD5 = 'md5'
SHA = 'sha1'


@contextlib.contextmanager
def runin(path):
    """Create a context to execure code in the specified working path."""
    oldcwd = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(oldcwd)


class trap_stdout(contextlib.redirect_stdout):  # noqa
    """Context manager for temporarily redirecting stdout to another file.

    Behaves just like :class:`contextlib.redirect_stdout` but if
    the `new_target` is not specified it defaults to :class:`io.StringIO`.
    """

    def __init__(self, new_target=None):
        if new_target is None:
            new_target = StringIO()
        super().__init__(new_target)


class trap_stderr(contextlib.redirect_stderr):  # noqa
    """Context manager for temporarily redirecting stderr to another file.

    Behaves just like :class:`contextlib.redirect_stderr` but if
    the `new_target` is not specified it defaults to :class:`io.StringIO`.
    """

    def __init__(self, new_target=None):
        if new_target is None:
            new_target = StringIO()
        super().__init__(new_target)


class ComputeSumTestCase(unittest.TestCase):
    ALGO = MD5
    COMMON_OPTIONS = []

    def setUp(self):
        logging.basicConfig(format=hashsum.LOGFMT, level=logging.INFO)
        logging.captureWarnings(True)

        self._old_stream = logging.getLogger().handlers[0].stream
        self.stderr = StringIO()
        logging.getLogger().handlers[0].stream = self.stderr

    def tearDown(self):
        logging.getLogger().handlers[0].stream = self._old_stream

    def test_binary(self):
        argv = self.COMMON_OPTIONS + [
            '-a', self.ALGO,
            '-b',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), trap_stdout() as out, trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.getvalue()

        with open(os.path.join(DATAPATH, 'MD5SUM_binary.txt')) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())

    def test_binary_auto(self):
        argv = self.COMMON_OPTIONS + [
            '-b',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]

        with warnings.catch_warnings():
            # Cause all warnings to always be triggered.
            warnings.simplefilter("always")

            with trap_stdout(), trap_stderr(self.stderr) as err:
                with runin(DATAPATH):
                    exitcode = hashsum.main(*argv)

            self.assertEqual(exitcode, hashsum.EX_OK)
            self.assertTrue('warning' in err.getvalue().lower())

    def test_binary_outfile(self):
        argv = self.COMMON_OPTIONS + [
            '-b',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), trap_stdout() as out, trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.getvalue()

        with open(os.path.join(DATAPATH, 'MD5SUM_binary.txt')) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())

    def test_binary_bsd(self):
        argv = self.COMMON_OPTIONS + [
            '--tag',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), trap_stdout() as out, trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.getvalue()

        with open(os.path.join(DATAPATH, 'MD5SUM_bsd.txt')) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())

    def test_text(self):
        argv = self.COMMON_OPTIONS + [
            '-t',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), trap_stdout() as out, trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.getvalue()

        if sys.platform.startswith('win'):
            checksumfile = 'MD5SUM_text_win.txt'
        else:
            checksumfile = 'MD5SUM_text_unix.txt'

        with open(os.path.join(DATAPATH, checksumfile)) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())


class ThreadedComputeSumTestCase(ComputeSumTestCase):
    COMMON_OPTIONS = ['-m']


class CheckTestCase(unittest.TestCase):
    ALGO = MD5
    COMMON_OPTIONS = []

    def setUp(self):
        logging.basicConfig(format=hashsum.LOGFMT, level=logging.INFO)
        logging.captureWarnings(True)

        self._old_stream = logging.getLogger().handlers[0].stream
        self.stderr = StringIO()
        logging.getLogger().handlers[0].stream = self.stderr

    def tearDown(self):
        logging.getLogger().handlers[0].stream = self._old_stream

    def test_binary(self):
        argv = self.COMMON_OPTIONS + [
            '-a', self.ALGO,
            '-c', os.path.join(DATAPATH, 'MD5SUM_binary.txt'),
        ]
        with runin(DATAPATH), trap_stdout(), trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_bsd_auto(self):
        argv = self.COMMON_OPTIONS + [
            '-c', os.path.join(DATAPATH, 'MD5SUM_bsd.txt'),
        ]
        with runin(DATAPATH), trap_stdout(), trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_bsd_algoname(self):
        argv = self.COMMON_OPTIONS + [
            '-a', self.ALGO,
            '-c', os.path.join(DATAPATH, 'MD5SUM_bsd.txt'),
        ]
        with runin(DATAPATH), trap_stdout(), trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_bsd_algoname_mismatch(self):
        argv = self.COMMON_OPTIONS + [
            '-a', SHA if SHA != self.ALGO else MD5,
            '-c', os.path.join(DATAPATH, 'MD5SUM_bsd.txt'),
        ]

        with runin(DATAPATH), trap_stdout(), trap_stderr(self.stderr) as err:
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_FAILURE)
        self.assertTrue('ERROR' in err.getvalue())

    def test_binary_bad_format(self):
        argv = self.COMMON_OPTIONS + [
            '-a', self.ALGO,
            '-c', os.path.join(DATAPATH, 'MD5SUM_binary_bad.txt'),
        ]

        with trap_stdout() as out, trap_stderr(self.stderr) as err:
            with runin(DATAPATH):
                exitcode = hashsum.main(*argv)

        self.assertEqual(exitcode, hashsum.EX_FAILURE)
        self.assertIn('file01.dat: OK', out.getvalue())
        self.assertIn('file02.dat: BAD_FORMATTING', out.getvalue())
        self.assertIn('file03.dat: FAILURE', out.getvalue())
        self.assertIn('WARNING: 1 computed checksum do NOT match',
                      err.getvalue())

    def test_binary_openssl(self):
        argv = self.COMMON_OPTIONS + [
            '-c', os.path.join(DATAPATH, 'SHASUM_openssl.txt'),
        ]
        with runin(DATAPATH), trap_stdout(), trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_openssl_bad_algoname(self):
        argv = self.COMMON_OPTIONS + [
            '-c', os.path.join(DATAPATH, 'SHASUM_openssl_bad_algoname.txt'),
        ]
        with runin(DATAPATH), trap_stdout(), trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_FAILURE)
        self.assertIn(
            'ERROR: unsupported hash type SH', self.stderr.getvalue())

    def test_text(self):
        if sys.platform.startswith('win'):
            checksumfile = 'MD5SUM_text_win.txt'
        else:
            checksumfile = 'MD5SUM_text_unix.txt'

        argv = ['-c', os.path.join(DATAPATH, checksumfile)]
        with runin(DATAPATH), trap_stdout(), trap_stderr():
            exitcode = hashsum.main(*argv)
        self.assertEqual(exitcode, hashsum.EX_OK)


class ThreadedCheckTestCase(CheckTestCase):
    COMMON_OPTIONS = ['-m']


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


if __name__ == '__main__':
    print_versions()
    unittest.main()
