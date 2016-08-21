hashsum changelog
=================

hashsum v1.1.2 (in development)
-------------------------------

* Improved compatibility with the OpenSSL command line tool
* Better iteration on data blocks


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
* Added :file:`NEWS.rst` file
* Added man page
* Improved command line help (also fixed some typos)
* Enabled automatic testing with travis-ci


hashsum v1.0 (04/01/2016)
-------------------------

* Initial release
