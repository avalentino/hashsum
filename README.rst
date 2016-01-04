hashsum
=======

:copiright: 2016 Antonio Valentino <antonio dot valentino at tiscali dot it>

Python drop-in replacement for ms5sum, and co.

::

    usage: hashsum [-h] [-a] [--tag] [-b | -t] [-c | -l] [--quiet] [--status]
                   [--strict] [-w] [--version]
                   [FILE [FILE ...]]

    Compute and check message digest for different hash algorithms.

    positional arguments:
      FILE                  name of file to proceess. If not specified, or set to
                            -, data are read form the standard input

    optional arguments:
      -h, --help            show this help message and exit
      -a , --algorithm      specify the hashing algorithm (default: MD5)
      --tag                 create a BSD-style checksum
      -b, --binary          read imput data in binary mode
      -t, --text            read imput data in text mode (default)
      -c, --check           read checksum(s) form FILE and check tham
      -l, --list-algorithms
                            list available hashing algorithms
      --version             show program's version number and exit

    check:
      Options that are useful only when verifying checksums

      --quiet               don't print OK for each successfully verified file
      --status              don't output anything, status code shows success
      --strict              exit non-zero for improperly formatted checksum lines
      -w, --warn            warn about improperly formatted checksum lines
