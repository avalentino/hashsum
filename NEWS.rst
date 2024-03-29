hashsum changelog
=================

hashsum v1.4.2 (UNRELEASED)
---------------------------

* TBW


hashsum v1.4.1 (18/07/2021)
---------------------------

* Fix the wheel generation: generated wheel are not universal,
  they only work with Python 3.6 and higher.


hashsum v1.4.0 (18/07/2021)
---------------------------

* Drop support for Python < 3.6.
* Switch to GitHub Actions for CI.
* Fix verification of checksums in text mode on Windows.
* Re-factorize and simplify the test code.
* Add buildsystem support (`pyproject.toml`)
* Switch to declarative setup configuration (`setup.cfg`).


hashsum v1.3.0 (25/08/2019)
---------------------------

* hashsum.VERSION renamed into hashsum.__version__
* added test utility functions
* prefer lowercase names for hash functions
* improve robustness against unknown/unavailable hash functions in
  threaded checksum computation
* new `--failfast` option added to the test CLI
* improved benchmark script
* man page updated
* improved compatibility with `pytest <https://pytest.org>`_


hashsum v1.2.2 (15/11/2016)
---------------------------

* Fix compatibility with the windows operating system


hashsum v1.2.1 (24/08/2016)
---------------------------

* Minor packaging fixes


hashsum v1.2.0 (24/08/2016)
---------------------------

* Improved compatibility with the OpenSSL command line tool
* Better iteration on data blocks
* Optional threaded hash computation
* Refactoring: the entire code has been re-organized in tools
* Drop all `gettext` related files


hashsum v1.1.1 (30/01/2016)
---------------------------

* Include man pages in the tarball


hashsum v1.1 (30/01/2016)
-------------------------

* Fixed IncrementalNewlineDecoder.decoder signature
* Always call decode with final=True when reading in text mode
* Factorized code for checksum computation
* All `Exceptions` are now trapped in the `main` function
* Added unit testing
* Code cleanup
* Added `NEWS.rst` file
* Added man page
* Improved command line help (also fixed some typos)
* Enabled automatic testing with travis-ci


hashsum v1.0 (04/01/2016)
-------------------------

* Initial release
