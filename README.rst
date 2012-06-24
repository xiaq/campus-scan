=================
Campus-Scan Howto
=================

Dependencies
============

* Nmap. Install it with your package manager (apt, yum, pacman, ports
  collection, whatever), all Unix distributions have it.  :)

* Python 2. Only Python 2.7 was tested, but Python 2.5+ is supposed to be
  supported. The shebang line of ``main.py`` was suitable for Archlinux. For
  other distributions, you may need to do::

   sed -e '1s/python2/python/' -i main.py

* Python packages: ``numpy``, ``matplotlib``, ``nmap`` and ``ipaddr``. Some of
  these may be available from your distribution. You can always install a
  Python package with with ``easy_install`` or ``pip`` (the latter being
  preferred).

Usage
=====

main.py::

 ./main.py {task} {verb}

``{task}`` is one of ``uphosts`` and ``openports``, ``{verb}`` one of ``scan``
and ``plot``.

The ``scan`` verb dumps results to ``stdout`` in JSON format. Specially,
``./main.py openports scan`` accepts an additional `subnet` argument, in the
format of CIDR. The default is ``59.66.0.0/16``.

The ``plot`` verb reads input from ``stdin`` and generates diagrams. The input
should have been created by the ``scan`` verb. It always accepts an additional
argument, namely the directory to put the generated diagrams. The default is
``.``, the current working directory. The directory should already exist.

Example::

  ./main.py uphosts scan > uphosts.json
  ./main.py uphosts plot < uphosts.json

You might want to run the ``scan`` as root (so that raw socket is available)
for better performance.

A shell script ``run.sh`` is provided to faciliate routine execution of the
tasks.

License
=======

All files are distributed under the terms of the ISC license, which is
effectively equivalent to 2-clause BSD license.  See ``COPYING`` for a copy of
the license.

