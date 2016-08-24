# -*- coding: utf-8 -*-

import os
import sys
import warnings
import contextlib


if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from io import BytesIO as StringIO


__all__ = (
    'TESTDIRPATH', 'fixpath', 'runin',
    'TrapOutput', 'redirect_stdout', 'redirect_stdout',
)

TESTDIRPATH = os.path.abspath(os.path.dirname(__file__))


def fixpath():
    pkgpath = os.path.normpath(os.path.dirname(TESTDIRPATH))
    sys.path.insert(0, pkgpath)


@contextlib.contextmanager
def runin(path):
    oldcwd = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(oldcwd)


class TrapOutput(object):
    def __init__(self, stdout=None, stderr=None):
        if stdout is None:
            stdout = StringIO()
        if stderr is None:
            stderr = StringIO()

        self._old_stdout = sys.stdout
        self._old_stderr = sys.stderr
        self.stdout = stdout
        self.stderr = stderr

    def __enter__(self):
        if self.stdout is not False:
            sys.stdout = self.stdout
        if self.stderr is not False:
            sys.stderr = self.stderr
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        sys.stdout = self._old_stdout
        sys.stderr = self._old_stderr


try:
    from contextlib import redirect_stdout
except ImportError:
    class redirect_stdout(object):
        """Context manager for temporarily redirecting stdout to another file.

            # How to send help() to stderr
            with redirect_stdout(sys.stderr):
                help(dir)

            # How to write help() to a file
            with open('help.txt', 'w') as f:
                with redirect_stdout(f):
                    help(pow)
        """

        _stream = "stdout"

        def __init__(self, new_target):
            self._new_target = new_target
            # We use a list of old targets to make this CM re-entrant
            self._old_targets = []

        def __enter__(self):
            self._old_targets.append(getattr(sys, self._stream))
            setattr(sys, self._stream, self._new_target)
            return self._new_target

        def __exit__(self, exctype, excinst, exctb):
            setattr(sys, self._stream, self._old_targets.pop())


try:
    from contextlib import redirect_stderr
except ImportError:
    class redirect_stderr(object):
        """Context manager for temporarily redirecting stderr to another file."""

        _stream = "stderr"

        def __init__(self, new_target):
            self._new_target = new_target
            # We use a list of old targets to make this CM re-entrant
            self._old_targets = []

        def __enter__(self):
            self._old_targets.append(getattr(sys, self._stream))
            setattr(sys, self._stream, self._new_target)
            return self._new_target

        def __exit__(self, exctype, excinst, exctb):
            setattr(sys, self._stream, self._old_targets.pop())


if sys.version_info < (3, 4):

    class catch_warnings(warnings.catch_warnings):
        def __enter__(self):
            try:
                module = sys.modules['hashsum']
                registry = getattr(module, '__warningregistry__')
            except (AttributeError, KeyError):
                pass
            else:
                registry.clear()

            return super(catch_warnings, self).__enter__()

else:
    catch_warnings = warnings.catch_warnings
