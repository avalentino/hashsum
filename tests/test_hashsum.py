#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import sys
import logging
import unittest
import warnings
from ._test_utils import (
    TESTDIRPATH, fixpath, runin, TrapOutput, catch_warnings
)


if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from io import BytesIO as StringIO


fixpath()


import hashsum


DATAPATH = os.path.join(TESTDIRPATH, 'data')


class ComputeSumTestCase(unittest.TestCase):
    ALGO = 'MD5'
    COMMON_OPTIONS = []

    def setUp(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(name)s: %(levelname)s: %(message)s')

        logging.captureWarnings(True)

        self._old_stream = logging.getLogger().handlers[0].stream
        self.stderr = StringIO()
        logging.getLogger().handlers[0].stream = self.stderr

    def tearDown(self):
        logging.getLogger().handlers[0].stream = self._old_stream

    def test_binary_01(self):
        argv = self.COMMON_OPTIONS + [
            '-a', self.ALGO,
            '-b',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), TrapOutput() as out:
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.stdout.getvalue()

        with open(os.path.join(DATAPATH, 'MD5SUM_binary.txt')) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())

    def test_binary_02(self):
        argv = self.COMMON_OPTIONS + [
            '-b',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]

        with catch_warnings():
            # Cause all warnings to always be triggered.
            warnings.simplefilter("always")

            with runin(DATAPATH), TrapOutput(stderr=self.stderr) as out:
                exitcode = hashsum.main(argv)

            self.assertEqual(exitcode, hashsum.EX_OK)
            self.assertTrue('WARNING' in out.stderr.getvalue())

    def test_binary_03(self):
        argv = self.COMMON_OPTIONS + [
            '-b',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), TrapOutput() as out:
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.stdout.getvalue()

        with open(os.path.join(DATAPATH, 'MD5SUM_binary.txt')) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())

    def test_binary_bsd(self):
        argv = self.COMMON_OPTIONS + [
            '--tag',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), TrapOutput() as out:
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.stdout.getvalue()

        with open(os.path.join(DATAPATH, 'MD5SUM_bsd.txt')) as fd:
            refdata = fd.read()

        self.assertEqual(refdata.strip(), data.strip())

    def test_text(self):
        argv = self.COMMON_OPTIONS + [
            '-t',
            'file01.dat', 'file02.dat', 'file03.dat',
        ]
        with runin(DATAPATH), TrapOutput() as out:
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)
        data = out.stdout.getvalue()

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
    ALGO = 'MD5'
    COMMON_OPTIONS = []

    def setUp(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(name)s: %(levelname)s: %(message)s')

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
        with runin(DATAPATH), TrapOutput():
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_bsd_01(self):
        argv = self.COMMON_OPTIONS + [
            '-c', os.path.join(DATAPATH, 'MD5SUM_bsd.txt'),
        ]
        with runin(DATAPATH), TrapOutput():
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_bsd_02(self):
        argv = self.COMMON_OPTIONS + [
            '-a', self.ALGO,
            '-c', os.path.join(DATAPATH, 'MD5SUM_bsd.txt'),
        ]
        with runin(DATAPATH), TrapOutput():
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_binary_bsd_03(self):
        argv = self.COMMON_OPTIONS + [
            '-a', 'SHA' if 'SHA' != self.ALGO else 'MD5',
            '-c', os.path.join(DATAPATH, 'MD5SUM_bsd.txt'),
        ]

        with runin(DATAPATH), TrapOutput(stderr=self.stderr) as out:
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_FAILURE)
        self.assertTrue('ERROR' in out.stderr.getvalue())

    def test_binary_openssl(self):
        argv = self.COMMON_OPTIONS + [
            '-c', os.path.join(DATAPATH, 'SHASUM_openssl.txt'),
        ]
        with runin(DATAPATH), TrapOutput():
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)

    def test_text(self):
        if sys.platform.startswith('win'):
            checksumfile = 'MD5SUM_text_win.txt'
        else:
            checksumfile = 'MD5SUM_text_unix.txt'

        argv = ['-c', os.path.join(DATAPATH, checksumfile)]
        with runin(DATAPATH), TrapOutput():
            exitcode = hashsum.main(argv)
        self.assertEqual(exitcode, hashsum.EX_OK)


class ThreadedCheckTestCase(CheckTestCase):
    COMMON_OPTIONS = ['-m']


if __name__ == '__main__':
    unittest.main()
