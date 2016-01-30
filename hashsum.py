#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import io
import os
import re
import sys
import enum
import codecs
import gettext
import hashlib
import logging
import argparse
import warnings


gettext.textdomain('hashsum')
_ = gettext.gettext


VERSION = '1.1'

EX_OK = os.EX_OK
EX_FAILURE = 1


DIGEST_LINE_RE = re.compile(
    '^\s*(?P<digest>\w+) (?P<binary>[ *])(?P<path>.+)$')
DIGEST_LINE_BSD_RE = re.compile(
    '^\s*(?P<algo>\w+) \((?P<path>.+)\) = (?P<digest>\w+)$')


class IncrementalNewlineDecoder(codecs.IncrementalDecoder):
    def __init__(self, errors='strict'):
        super(IncrementalNewlineDecoder, self).__init__(errors=errors)
        self.buffer = b''
        self.from_ = os.linesep.encode('ascii')
        self.to = b'\n'

    def decode(self, data, final=False):
        if self.buffer:
            output = self.buffer + data
        else:
            output = data

        self.buffer = b''
        if len(self.from_) > 1:
            assert(len(self.from_) == 2)
            lastchar = self.from_[-2]
            if output.endswith(lastchar) and not final:
                output = output[:-1]
                self.buffer = lastchar

        output = output.replace(self.from_, self.to)

        return output

    def reset(self):
        super(IncrementalNewlineDecoder, self).reset()
        self.buffer = b''

    def getstate(self):
        return self.buffer, 0

    def setstate(self, state):
        self.buffer = state[0]


class CheckResult(enum.Enum):
    ok = 0
    failure = 1
    improperly_formatted = 2
    ignored = 3


class CheckResultData(object):
    def __init__(self, n_ok=0, n_failures=0, n_improperly_formatted=0,
                 n_ignored=0):
        self.n_ok = n_ok
        self.n_failures = n_failures
        self.n_improperly_formatted = n_improperly_formatted
        self.n_ignored = n_ignored

    def update(self, ret):
        if ret == CheckResult.ok:
            self.n_ok += 1
        elif ret == CheckResult.failure:
            self.n_failures += 1
        elif ret == CheckResult.improperly_formatted:
            self.n_improperly_formatted += 1
        elif ret == CheckResult.ignored:
            self.n_ignored += 1
        else:
            raise ValueError(_('unexpected value: {}').format(ret))


def decode_checksum_file_line(line, algo=None):
    mobj = DIGEST_LINE_BSD_RE.match(line)
    if mobj:
        if algo is not None and algo != mobj.group('algo'):
            msg = _('specified hashing algorithm ({}) is different form '
                    'the one used in the digest file ({})')
            raise ValueError(msg.format(algo, mobj.group('algo')))
        algo = mobj.group('algo')
        path = mobj.group('path')
        hexdigest = mobj.group('digest')
        binary = True
    else:
        mobj = DIGEST_LINE_RE.match(line)
        if not mobj:
            raise ValueError(
                _('unble to decode digest line: "{}"').format(line))
        path = mobj.group('path')
        hexdigest = mobj.group('digest')
        binary = True if mobj.group('binary') else False
        if algo is None:
            msg = _('no algorithm specified; using MD5')
            warnings.warn(msg)
            algo = 'MD5'

    return path, hexdigest, binary, algo


def compute_file_checksum(fd, algo='MD5', binary=True):
    hash_obj = hashlib.new(algo)

    if not binary and os.linesep != '\n':
        decoder = IncrementalNewlineDecoder()
    else:
        decoder = None

    for data in fd:
        if decoder:
            data = decoder.decode(data)
        hash_obj.update(data)

    if decoder:
        data = decoder.decode(b'', final=True)
        hash_obj.update(data)

    return hash_obj


def process_checksum_file_line(line, algo=None, quiet=False, status=False):
    if len(line) == 0 or line[0] == '#':
        # support for comments in the digest-file
        return CheckResult.ignored

    path, hexdigest, binary, algo = decode_checksum_file_line(line, algo)

    with io.open(path, 'rb') as fd:
        hash_obj = compute_file_checksum(fd, algo, binary)

    if hash_obj.hexdigest() == hexdigest:
        result = CheckResult.ok
    else:
        result = CheckResult.failure
        if len(hash_obj.hexdigest()) != len(hexdigest):
            result = CheckResult.improperly_formatted

    if not status and result in (CheckResult.ok, CheckResult.failure):
        if (result == CheckResult.failure) or not quiet:
            print('{}: {}'.format(path, result.name.upper()))

    return result


def print_check_results(check_result, filename, status=False, warn=False,
                        strict=False):
    ret = True
    log = logging.getLogger('hashsum')
    if check_result.n_failures > 0:
        if not status:
            msg = _('{} computed checksum did NOT match')
            log.warning(msg.format(check_result.n_failures))
        ret = False

    if check_result.n_improperly_formatted > 0:
        if warn:
            msg = _('{} improperly formatted checksum line')
            log.warning(msg.format(check_result.n_improperly_formatted))
        if strict:
            ret = False

    if check_result.n_ok == 0:
        msg = _('{}: no properly formatted checksum lines found')
        log.info(msg.format(filename))
        ret = False

    return ret


def verify_checksums(filenames, algo=None, quiet=False, status=False,
                     warn=False, strict=False):
    result = True
    if filenames:
        for filename in filenames:
            check_result = CheckResultData()
            with open(filename) as fd:
                for line in fd:
                    ret = process_checksum_file_line(line, algo, quiet, status)
                    check_result.update(ret)

                ret = print_check_results(check_result, filename, status, warn,
                                          strict)
                if not ret:
                    result = False

    else:
        filename = '-'
        check_result = CheckResultData()
        for line in sys.stdin:
            ret = process_checksum_file_line(line, algo, quiet, status)
            check_result.update(ret)

        ret = print_check_results(check_result, filename, status, warn, strict)
        if not ret:
            result = False

    return result


def print_hash_line(filename, hash_obj, tag=False, binary=False):
    algo = hash_obj.name
    if algo.upper() in hashlib.algorithms_available:
        algo = algo.upper()

    if tag:
        print('{} ({}) = {}'.format(algo, filename, hash_obj.hexdigest()))
    else:
        marker = '*' if binary else ' '
        print('{} {}{}'.format(hash_obj.hexdigest(), marker, filename))


def compute_checksums(filenames, algo=None, binary=None, tag=False):
    if algo is None:
        msg = _('no algorithm specified; using MD5')
        warnings.warn(msg)
        algo = 'MD5'

    if tag and not binary:
        raise ValueError(_('binary option set to False in incompatible with '
                           'tag option set to Ture'))

    if filenames:
        for filename in filenames:
            if os.path.isdir(filename):
                log = logging.getLogger('hashsum')
                msg = _('{}: is a directory')
                log.info(msg.format(filename))
                continue

            with io.open(filename, 'rb') as fd:
                hash_obj = compute_file_checksum(fd, algo, binary)

            print_hash_line(filename, hash_obj, tag, binary)
    else:
        filename = '-'

        if sys.version_info[0] < 3:
            stdin = sys.stdin
            if os.linesep != '\n' and binary:
                try:
                    import msvcrt
                    msvcrt.setmode(stdin, os.O_BINARY)
                except (ImportError, AttributeError):
                    msg = _('binary mode is not supported for stdin on this '
                            'platform')
                    raise ValueError(msg)
        else:
            stdin = sys.stdin.buffer

        hash_obj = compute_file_checksum(stdin, algo, binary)
        print_hash_line(filename, hash_obj, tag, binary)


def get_parser():
    description = _(
        '''Compute and check message digest with different hash algorithms.

The sums are computed as described in
https://docs.python.org/3/library/hashlib.html.
When checking, the input should be a former output of this program.
The default mode is to print a line with checksum, a character indicating
input mode ('*' for binary, space for text), and name for each FILE.
''')

    epilog = _('''Copyright (C) 2016, Antonio Valentino''')

    parser = argparse.ArgumentParser(
            prog='hashsum', description=description,
            epilog=epilog)
    parser.add_argument(
        '-a', '--algorithm', choices=hashlib.algorithms_available,
        default=None, metavar='',
        help=_('specify the hashing algorithm (default: MD5)'))
    parser.add_argument(
        '--tag', action='store_true', default=False,
        help=_('create a BSD-style checksum'))

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '-b', '--binary', action='store_true', default=None,
        help=_('read input data in binary mode'))
    mode_group.add_argument(
        '-t', '--text', dest='binary', action='store_false',
        help=_('read input data in text mode (default)'))

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-c', '--check', action='store_true', default=False,
        help=_('read checksum(s) form FILE and check them'))
    group.add_argument(
        '-l', '--list-algorithms', action='store_true', default=False,
        help=_('list available hashing algorithms'))

    check_group = parser.add_argument_group(
        'check',
        _('Options that are useful only when verifying checksums'))
    check_group.add_argument(
        '--quiet', action='store_true', default=False,
        help=_("don't print OK for each successfully verified file"))
    check_group.add_argument(
        '--status', action='store_true', default=False,
        help=_("don't output anything, status code shows success"))
    check_group.add_argument(
        '--strict', action='store_true', default=False,
        help=_("exit non-zero for improperly formatted checksum lines"))
    check_group.add_argument(
        '-w', '--warn', action='store_true', default=False,
        help=_("warn about improperly formatted checksum lines"))

    parser.add_argument(
        '--version', action='version', version='%(prog)s v{}'.format(VERSION))
    parser.add_argument(
        'filenames', nargs='*', metavar='FILE',
        help=_('name of file to process. '
               'If not specified, or set to -, data are read form the '
               'standard input'))

    return parser


def parse_arguments(parser, argv=None):
    args = parser.parse_args(argv)

    if args.tag:
        if args.binary is False:
            parser.error(_('--tag does not support --text mode'))
        else:
            args.binary = True

    if args.tag and args.check:
        parser.error(
            _('the --tag option is meaningless when verifying checksums'))

    if args.binary and args.check:
        parser.error(_('the --binary and --text options are meaningless '
                       'when verifying checksums'))

    if args.status and not args.check:
        parser.error(_('the --status option is meaningful only when '
                       'verifying checksums'))

    if args.warn and not args.check:
        parser.error(_('the --warn option is meaningful only when '
                       'verifying checksums'))

    if args.quiet and not args.check:
        parser.error(_('the --quiet option is meaningful only when '
                       'verifying checksums'))

    if args.strict and not args.check:
        parser.error(_('the --strict option is meaningful only when '
                       'verifying checksums'))

    if '-' in args.filenames:
        if len(args.filenames) > 1:
            parser.error(_('"-" cannot be used if other file names have '
                           'been specified'))
        else:
            args.filenames.remove('-')

    return args


def main(argv=None):
    logging.basicConfig(
        level=logging.INFO,
        format='%(name)s: %(levelname)s: %(message)s')

    logging.captureWarnings(True)

    parser = get_parser()
    args = parse_arguments(parser, argv)
    exitcode = EX_OK

    try:
        if args.list_algorithms:
            algoset = hashlib.algorithms_available
            algolist = sorted(
                algo for algo in algoset
                if algo.isupper() or algo.upper() not in algoset
            )
            print(_('Available hash algoritms:'))
            print('  ', '\n  '.join(algolist), sep='')
        elif args.check:
            result = verify_checksums(args.filenames, args.algorithm,
                                      args.quiet, args.status, args.warn,
                                      args.strict)
            if not result:
                return EX_FAILURE
        else:
            compute_checksums(
                args.filenames, args.algorithm, args.binary, args.tag)
    except Exception as e:
        exitcode = EX_FAILURE
        log = logging.getLogger('hashsum')
        log.error(e)

    return exitcode


if __name__ == '__main__':
    sys.exit(main())
