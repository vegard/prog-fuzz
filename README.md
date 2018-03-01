Program fuzzer
==============

Introduction
------------

Very WIP/PoC code. Proceed with caution.

Many thanks to lcamtuf, the AFL people, John Regehr and the C-Reduce people,
and the GCC people.


Usage
-----

1. Download AFL to the current directory.
2. Build it.
4. Build your compiler using `afl-gcc`.
3. Change `$AFL_PATH` in `make.sh` if necessary.
5. Look for `execlp` in `main.cc` and point it to your instrumented compiler.
6. Run `make.sh`.
7. Run `./main`.


License
-------

The project includes snippets from AFL (Apache 2.0) and gcc (GPL 3),
therefore this project is naturally GPL 3 as well.


Reported bugs
-------------

GCC:

* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84576>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84585>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84588>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84590>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84593>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84596>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84598>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84602>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84605>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84606>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84608>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84609>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84610>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84611>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84618>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84630>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84632>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84633>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84636>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84638>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84642>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84644>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84647>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84651>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84652>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84653>
* <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=84655>
