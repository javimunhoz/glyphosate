Glyphosate
==========

This project explores computer virus signature matching using bit string
abstractions and functional programming. It implements detection and
disinfection routines for a real computer virus (Win32.H0rtiga)

Source code is implemented with OCaml.

More information about this project:

[http://javiermunhoz.com/blog/2014/04/19/detecting-and-removing-computer-virus-with-ocaml.html](http://javiermunhoz.com/blog/2014/04/19/detecting-and-removing-computer-virus-with-ocaml.html)

Licensing
=========

Glyphosate is freely redistributable under the two-clause BSD License. Use of
this source code is governed by a BSD-style license that can be found in the
`LICENSE` file.

Dependencies
============

1. This code was developed and tested in a GNU/Linux system ([Debian GNU/Linux](http://www.debian.org))
2. It requires OCaml installed

Compiling and running
=====================

1. Grab the code with Git. Use the following command:

   ~$ git clone https://github.com/javimunhoz/glyphosate

2. Compile the sources

   ~$ cd glyphosate/src

   ~$ make

3. Run it

   ~$ ./test.out file.exe
