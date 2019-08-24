#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from . import test


parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', dest='verbosity',
                    action='store_const', const=2, default=1,
                    help='Verbose output')
parser.add_argument('-q', '--quiet', dest='verbosity',
                    action='store_const', const=0, default=1,
                    help='Quiet output')
parser.add_argument('-f', '--failfast', action='store_true', default=False,
                    help='Stop the test run on the first error or failure')

args = parser.parse_args()

test(args.verbosity)
