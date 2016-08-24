hashsum
=======

Python drop-in replacement for md5sum, and co.
**********************************************


:copiright: 2016 Antonio Valentino <antonio dot valentino at tiscali dot it>

.. image:: https://travis-ci.org/avalentino/hashsum.svg?branch=master
    :target: https://travis-ci.org/avalentino/hashsum


Usage
-----

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
                            (default: MD5)
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
---------------

::

    $ python setyp.py test
