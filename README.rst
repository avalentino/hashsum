=======
hashsum
=======

Python drop-in replacement for md5sum, and co.
**********************************************

:HomePage: https://github.com/avalentino/hashsum
:Copyright: 2016-2021 Antonio Valentino <antonio dot valentino at tiscali dot it>

.. image:: https://img.shields.io/pypi/v/hashsum
    :alt: Latest Version
    :target: https://pypi.org/project/hashsum

.. image:: https://img.shields.io/pypi/pyversions/hashsum
    :alt: Supported Python versions
    :target: https://pypi.org/project/hashsum

.. image:: https://img.shields.io/pypi/l/hashsum
    :alt: License
    :target: https://pypi.org/project/hashsum

.. image:: https://github.com/avalentino/hashsum/actions/workflows/python-package.yml/badge.svg
    :alt: GHA status page
    :target: https://github.com/avalentino/hashsum/actions

.. image:: https://codecov.io/gh/avalentino/hashsum/branch/master/graph/badge.svg
    :alt: Coverage Status
    :target: https://codecov.io/gh/avalentino/hashsum


Usage
=====

::

    usage: hashsum [-h] [-a] [--tag] [-b | -t] [-c | -l] [--quiet]
                   [--status] [--strict] [-w] [-m] [--version]
                   [FILE [FILE ...]]

    Compute and check message digest with different hash algorithms.
    The sums are computed as described in [1].
    When checking, the input should be a former output of this program.
    The default mode is to print a line with checksum, a character
    indicating input mode ('*' for binary, space for text), and name
    for each FILE.

    [1] https://docs.python.org/3/library/hashlib.html

    positional arguments:
      FILE                  name of file to process. If not specified,
                            or set to -, data are read form the
                            standard input

    optional arguments:
      -h, --help            show this help message and exit
      -a , --algorithm      specify the hashing algorithm
                            (default: 'md5')
      --tag                 create a BSD-style checksum
      -b, --binary          read input data in binary mode
      -t, --text            read input data in text mode (default)
      -c, --check           read checksum(s) form FILE and check them
      -l, --list-algorithms
                            list available hashing algorithms
      -m, --multi-thread    perform I/O and hash computation in separate threads
                            (default=False). Can speed-up computation on large
                            files while it is not recommended for small files.
      --version             show program's version number and exit

    check:
      Options that are useful only when verifying checksums

      --quiet               don't print OK for each successfully
                            verified file
      --status              don't output anything, status code shows
                            success
      --strict              exit non-zero for improperly formatted
                            checksum lines
      -w, --warn            warn about improperly formatted checksum
                            lines


Package testing
===============

The recommended way to test the package is::

    $ python3 -m tests -v

it also prints some basic system information that can be sued for bug
reporting::

    hashsum version:      1.2.3.dev1
    Python version:       3.7.3
    Platform:             Linux-5.0.0-27-generic-x86_64-with-Ubuntu-19.04-disco
    Byte-ordering:        little
    Default encoding:     utf-8
    Default FS encoding:  utf-8
    Default locale:       (it_IT, UTF-8)

    test_binary (tests.test_hashsum.CheckTestCase) ... ok
    test_binary_bad_format (tests.test_hashsum.CheckTestCase) ... ok

    [...]

    test_binary_outfile (tests.test_hashsum.ThreadedComputeSumTestCase) ... ok
    test_text (tests.test_hashsum.ThreadedComputeSumTestCase) ... ok

    ----------------------------------------------------------------------
    Ran 26 tests in 0.037s

    OK

Alternatively it is possible to use::

    $ python3 setup.py test

or::

    $ python3 -m unittest -v

or e.g. `pytest <https://pytest.org>`_::

    $ python3 -m pytest -v

Please note that the default configuration for "pytest" is stored into the
`setup.cfg` file in the root directory of the source package::

    [tool:pytest]
    addopts = -p no:warnings -p no:logging


License
=======

The `hashsum` software is distribute under the terms of the
"3-Clause BSD License" see `LICENSE.txt` file for details.
