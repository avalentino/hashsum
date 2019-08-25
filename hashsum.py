#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compute and check message digest with different hash algorithms.

The sums are computed as described in [1].
When checking, the input should be a former output of this program.
The default mode is to print a line with checksum, a character indicating
input mode ('*' for binary, space for text), and name for each FILE.

[1] https://docs.python.org/3/library/hashlib.html
"""


from __future__ import print_function

import io
import os
import re
import sys
import enum
import codecs
import hashlib
import logging
import argparse
import warnings
import functools

try:
    from os import EX_OK
except ImportError:
    EX_OK = 0
EX_FAILURE = 1
EX_INTERRUPT = 130

try:
    import argcomplete
except ImportError:
    argcomplete = False
else:
    PYTHON_ARGCOMPLETE_OK = True


__version__ = '1.2.3.dev1'
PROG = os.path.splitext(os.path.basename(__file__))[0]
LOGFMT = '%(levelname)s: %(message)s'


DIGEST_LINE_RE = re.compile(
    r'^(?P<digest>\w+) (?P<binary>[ *])(?P<path>.+)$')
DIGEST_LINE_BSD_RE = re.compile(
    r'^(?P<algo>\w+)\ ?\((?P<path>.+)\)\ ?= (?P<digest>\w+)$')


BLOCKSIZE = 1024 * 1024     # 1MB
_QUEUE_LEN = 50             # max 50MB


DEFAULT_ALGO = 'md5'


def blockiter(fd, blocksize=io.DEFAULT_BUFFER_SIZE):
    '''Iterator on file-like objects that read blocks of the specified size

    The `fd` parameter must be a binary or text file-like object opened
    for reading.

    The `blocksize` parameter defaults to `io.DEFAULT_BUFFER_SIZE`.

    '''

    guard = '' if isinstance(fd, io.TextIOBase) else b''

    return iter(functools.partial(fd.read, blocksize), guard)


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
            lastchar = self.from_[-2:-2]
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
    OK = 0
    FAILURE = 1
    BAD_FORMATTING = 2
    IGNORED = 3


class CheckResultData(object):
    def __init__(self, n_ok=0, n_failures=0, n_improperly_formatted=0,
                 n_ignored=0):
        self.n_ok = n_ok
        self.n_failures = n_failures
        self.n_improperly_formatted = n_improperly_formatted
        self.n_ignored = n_ignored

    def update(self, ret):
        if ret == CheckResult.OK:
            self.n_ok += 1
        elif ret == CheckResult.FAILURE:
            self.n_failures += 1
        elif ret == CheckResult.BAD_FORMATTING:
            self.n_improperly_formatted += 1
        elif ret == CheckResult.IGNORED:
            self.n_ignored += 1
        else:
            raise ValueError('unexpected value: {}'.format(ret))


def _compute_file_checksum_sequential(fd, algo=DEFAULT_ALGO, binary=True):
    hash_obj = hashlib.new(algo)

    if not binary and os.linesep != '\n':
        decoder = IncrementalNewlineDecoder()
    else:
        decoder = None

    for data in blockiter(fd, BLOCKSIZE):
        if decoder:
            data = decoder.decode(data)
        hash_obj.update(data)

    if decoder:
        data = decoder.decode(b'', final=True)
        hash_obj.update(data)

    return hash_obj


class HashObjectData(object):
    def __init__(self, hash_obj):
        self.block_size = hash_obj.block_size
        self.name = hash_obj.name
        self.digest_size = hash_obj.digest_size
        self._digest = hash_obj.digest()
        self._hexdigest = hash_obj.hexdigest()

    def digest(self):
        return self._digest

    def hexdigest(self):
        return self._hexdigest


def _worker(tasks, results, algo=DEFAULT_ALGO, decoder=None):
    try:
        hash_obj = hashlib.new(algo)

        for data in iter(tasks.get, None):
            if decoder:
                data = decoder.decode(data)
            hash_obj.update(data)
            tasks.task_done()
        else:
            if decoder:
                data = decoder.decode(b'', final=True)
                hash_obj.update(data)
            tasks.task_done()  # for None

            results.put(HashObjectData(hash_obj))
    except Exception as exc:
        results.put(exc)


def _compute_file_checksum_threading(fd, algo=DEFAULT_ALGO, binary=True):
    try:
        import queue
    except ImportError:
        import Queue as queue
    import threading

    if not binary and os.linesep != '\n':
        decoder = IncrementalNewlineDecoder()
    else:
        decoder = None

    task_queue = queue.Queue(_QUEUE_LEN)
    result_queue = queue.Queue()

    args = (task_queue, result_queue, algo, decoder)
    worker = threading.Thread(name='worker', target=_worker, args=args)
    worker.start()

    try:
        for data in blockiter(fd, BLOCKSIZE):
            task_queue.put(data)
            if not result_queue.empty():
                break  # fail fast
    finally:
        task_queue.put(None)

    result = result_queue.get()
    worker.join()

    if isinstance(result, Exception):
        raise result

    return result


class ChecksumVerifier(object):
    def __init__(self, algo=None, quiet=False, status=False, warn=False,
                 strict=False, multi_thread=False):
        self.algo = algo
        self.quiet = quiet
        self.status = status
        self.warn = warn
        self.strict = strict
        self.multi_thread = multi_thread

    def _compute_file_checksum(self, fd, algo, binary):
        if self.multi_thread:
            return _compute_file_checksum_threading(fd, algo, binary)
        else:
            return _compute_file_checksum_sequential(fd, algo, binary)

    def _check_algorithm_compatibility(self, algo):
        if self.algo is not None and self.algo.lower() != algo.lower():
            raise ValueError(
                'specified hashing algorithm ({}) is different form '
                'the one used in the digest file ({})'.format(
                    self.algo, algo))

    def decode_checksum_file_line(self, line):
        mobj = DIGEST_LINE_BSD_RE.match(line)
        if mobj:
            self._check_algorithm_compatibility(mobj.group('algo'))
            algo = mobj.group('algo')
            path = mobj.group('path')
            hexdigest = mobj.group('digest')
            binary = True
        else:
            mobj = DIGEST_LINE_RE.match(line)
            if not mobj:
                raise ValueError(
                    'unble to decode digest line: "{}"'.format(line))
            path = mobj.group('path')
            hexdigest = mobj.group('digest')
            binary = True if mobj.group('binary') else False
            if self.algo is None:
                warnings.warn(
                    'no algorithm specified; using {!r}'.format(DEFAULT_ALGO))
                algo = DEFAULT_ALGO
            else:
                algo = self.algo

        return path, hexdigest, binary, algo

    def process_checksum_file_line(self, line):
        if len(line) == 0 or line[0] == '#':
            # support for comments in the digest-file
            return CheckResult.IGNORED

        path, hexdigest, binary, algo = self.decode_checksum_file_line(line)

        with io.open(path, 'rb') as fd:
            hash_obj = self._compute_file_checksum(fd, algo, binary)

        if hash_obj.hexdigest() == hexdigest:
            result = CheckResult.OK
        elif len(hash_obj.hexdigest()) != len(hexdigest):
            result = CheckResult.BAD_FORMATTING
        else:
            result = CheckResult.FAILURE

        if not self.status and result in (CheckResult.OK, CheckResult.FAILURE):
            if (result == CheckResult.FAILURE) or not self.quiet:
                print('{}: {}'.format(path, result.name.upper()))

        return result

    def print_check_results(self, check_result, filename):
        ret = True
        log = logging.getLogger('hashsum')
        if check_result.n_failures > 0:
            if not self.status:
                log.warning(
                    '{} computed checksum do NOT match'.format(
                        check_result.n_failures))
            ret = False

        if check_result.n_improperly_formatted > 0:
            if self.warn:
                log.warning(
                '{} improperly formatted checksum line'.format(
                    check_result.n_improperly_formatted))
            if self.strict:
                ret = False

        if check_result.n_ok == 0:
            log.info(
                '{}: no properly formatted checksum lines found'.format(
                    filename))
            ret = False

        return ret

    def verify_checksums(self, filenames):
        result = True
        if filenames:
            if isinstance(filenames, str):
                filenames = [filenames]

            for filename in filenames:
                check_result = CheckResultData()
                with open(filename) as fd:
                    for line in fd:
                        ret = self.process_checksum_file_line(line)
                        check_result.update(ret)

                ret = self.print_check_results(check_result, filename)
                if not ret:
                    result = False

        else:
            # filenames is None or an empty list
            filename = '-'
            check_result = CheckResultData()
            for line in sys.stdin:
                ret = self.process_checksum_file_line(line)
                check_result.update(ret)

            ret = self.print_check_results(check_result, filename)
            if not ret:
                result = False

        return result


class ChecksumCalculator(object):
    def __init__(self, algo=None, binary=None, tag=False, multi_thread=False):
        self.algo = algo
        self.binary = binary
        self.tag = tag
        self.multi_thread = multi_thread

        if self.algo is None:
            warnings.warn(
                'no algorithm specified; using {!r}'.format(DEFAULT_ALGO))
            self.algo = DEFAULT_ALGO

        if self.tag and not self.binary:
            raise ValueError(
                'binary option set to False is incompatible with tag '
                'option set to Ture')

    def print_hash_line(self, filename, hash_obj):
        if self.tag:
            algo = hash_obj.name.upper()
            print('{} ({}) = {}'.format(algo, filename, hash_obj.hexdigest()))
        else:
            marker = '*' if self.binary else ' '
            print('{} {}{}'.format(hash_obj.hexdigest(), marker, filename))

    def _compute_file_checksum(self, fd):
        if self.multi_thread:
            return _compute_file_checksum_threading(fd, self.algo, self.binary)
        else:
            return _compute_file_checksum_sequential(fd, self.algo,
                                                     self.binary)

    def compute_checksums(self, filenames):
        if filenames:
            if isinstance(filenames, str):
                filenames = [filenames]

            for filename in filenames:
                if os.path.isdir(filename):
                    log = logging.getLogger('hashsum')
                    log.info('{}: is a directory'.format(filename))
                    continue

                with io.open(filename, 'rb') as fd:
                    hash_obj = self._compute_file_checksum(fd)

                self.print_hash_line(filename, hash_obj)
        else:
            # filenames is None or an empty list
            filename = '-'
            old_mode = None

            # stdin = io.open(sys.stdin.fileno(), mode='rb', closefd=False)
            if sys.version_info[0] < 3:
                stdin = sys.stdin
                if os.linesep != '\n' and self.binary:
                    try:
                        import msvcrt
                        msvcrt.setmode(stdin, os.O_BINARY)
                    except (ImportError, AttributeError):
                        raise ValueError(
                            'binary mode is not supported for stdin on '
                            'this platform')
                    else:
                        old_mode = os.O_TEXT
            else:
                stdin = sys.stdin.buffer

            try:
                hash_obj = self._compute_file_checksum(stdin)
                self.print_hash_line(filename, hash_obj)
            finally:
                if old_mode is not None:
                    msvcrt.setmode(stdin, old_mode)


def get_parser():
    """Instantiate the command line argument parser."""

    epilog = 'Copyright (C) 2016-2019, Antonio Valentino'

    parser = argparse.ArgumentParser(
            prog=PROG, description=__doc__, epilog=epilog)

    parser.add_argument(
        '-a', '--algorithm', choices=hashlib.algorithms_available,
        default=None, metavar='',
        help='specify the hashing algorithm '
             '(default: {!r})'.format(DEFAULT_ALGO))
    parser.add_argument(
        '--tag', action='store_true', default=False,
        help='create a BSD-style checksum')

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '-b', '--binary', action='store_true', default=None,
        help='read input data in binary mode')
    mode_group.add_argument(
        '-t', '--text', dest='binary', action='store_false',
        help='read input data in text mode (default)')

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-c', '--check', action='store_true', default=False,
        help='read checksum(s) form FILE and check them')
    group.add_argument(
        '-l', '--list-algorithms', action='store_true', default=False,
        help='list available hashing algorithms')

    check_group = parser.add_argument_group(
        'check', 'Options that are useful only when verifying checksums')
    check_group.add_argument(
        '--quiet', action='store_true', default=False,
        help="don't print OK for each successfully verified file")
    check_group.add_argument(
        '--status', action='store_true', default=False,
        help="don't output anything, status code shows success")
    check_group.add_argument(
        '--strict', action='store_true', default=False,
        help="exit non-zero for improperly formatted checksum lines")
    check_group.add_argument(
        '-w', '--warn', action='store_true', default=False,
        help="warn about improperly formatted checksum lines")

    parser.add_argument(
        '-m', '--multi-thread', action='store_true', default=False,
        help='perform I/O and hash computation in separate threads '
             '(default=%(default)s). '
             'Can speed-up computation on large files while it is not '
             'recommended for small files.')

    parser.add_argument(
        '--version', action='version',
        version='%(prog)s v{}'.format(__version__))
    parser.add_argument(
        'filenames', nargs='*', metavar='FILE',
        help='name of file to process. '
             'If not specified, or set to -, data are read form the '
             'standard input')

    if argcomplete:
        argcomplete.autocomplete(parser)

    return parser


def parse_args(args=None, namespace=None, parser=None):
    """Parse command line arguments."""

    if parser is None:
        parser = get_parser()

    args = parser.parse_args(args)

    if args.tag:
        if args.binary is False:
            parser.error('--tag does not support --text mode')
        else:
            args.binary = True

    if args.tag and args.check:
        parser.error(
            'the --tag option is meaningless when verifying checksums')

    if args.binary and args.check:
        parser.error('the --binary and --text options are meaningless '
                     'when verifying checksums')

    if args.status and not args.check:
        parser.error('the --status option is meaningful only when '
                     'verifying checksums')

    if args.warn and not args.check:
        parser.error('the --warn option is meaningful only when '
                     'verifying checksums')

    if args.quiet and not args.check:
        parser.error('the --quiet option is meaningful only when '
                     'verifying checksums')

    if args.strict and not args.check:
        parser.error('the --strict option is meaningful only when '
                     'verifying checksums')

    if '-' in args.filenames:
        if len(args.filenames) > 1:
            parser.error('"-" cannot be used if other file names have '
                         'been specified')
        else:
            args.filenames.remove('-')

    return args


def main(*argv):
    """Main CLI interface."""

    # setup logging
    logging.basicConfig(format=LOGFMT, level=logging.INFO)
    logging.captureWarnings(True)
    log = logging.getLogger('hashsum')

    # parse cmd line arguments
    args = parse_args(argv if argv else None)

    exitcode = EX_OK
    try:
        if args.list_algorithms:
            algoset = hashlib.algorithms_available
            algolist = sorted(
                algo for algo in algoset
                if algo.islower() or algo.lower() not in algoset
            )
            print('Available hash algoritms:')
            print('  ', '\n  '.join(algolist), sep='')
        elif args.check:
            tool = ChecksumVerifier(args.algorithm, args.quiet, args.status,
                                    args.warn, args.strict, args.multi_thread)
            result = tool.verify_checksums(args.filenames)
            if not result:
                exitcode = EX_FAILURE
        else:
            tool = ChecksumCalculator(
                args.algorithm, args.binary, args.tag, args.multi_thread)
            tool.compute_checksums(args.filenames)
    except Exception as exc:
        log.error(str(exc))
        log.debug('stacktrace:', exc_info=True)
        exitcode = EX_FAILURE
    except KeyboardInterrupt:
        log.warning('Keyboard interrupt received: exit the program')
        exitcode = EX_INTERRUPT

    return exitcode


if __name__ == '__main__':
    sys.exit(main())
