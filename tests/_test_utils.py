import os
import sys
import warnings
import contextlib
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr


__all__ = (
    'TESTDIRPATH', 'fixpath', 'runin',
    'TrapOutput', 'redirect_stdout', 'redirect_stderr',
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


# @TODO: replace with redirect_stdout and redirect_stderr
class TrapOutput:
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


catch_warnings = warnings.catch_warnings
