Examples
========

These are several sanitizers that demonstrate PyCIRCLean's capabilities. Feel free to
adapt or modify any of them to suit your requirements. In order to use any of these scripts,
you will first need to install the PyCIRCLean dependencies (preferably in a virtualenv):

```
    pip install .
```

Requirements per script
=======================

generic.py
----------

This is a script that was used by an older version of CIRCLean.

Requirements by type of document:
* Office and all text files: unoconv, libreoffice
* PDF: ghostscript, pdf2htmlEX

```
    # required for pdf2htmlEX
    sudo add-apt-repository ppa:fontforge/fontforge --yes
    sudo add-apt-repository ppa:coolwanglu/pdf2htmlex --yes
    sudo apt-get update -qq
    sudo apt-get install -qq libpoppler-dev libpoppler-private-dev libspiro-dev libcairo-dev libpango1.0-dev libfreetype6-dev libltdl-dev libfontforge-dev python-imaging python-pip firefox xvfb
    # install pdf2htmlEX
    git clone https://github.com/coolwanglu/pdf2htmlEX.git
    pushd pdf2htmlEX
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DENABLE_SVG=ON .
    make
    sudo make install
    popd
    # Installing the rest
    sudo apt-get install ghostscript p7zip-full p7zip-rar libreoffice unoconv
```

pier9.py
--------

This script contains a list of file formats for various brands of industrial
manufacturing equipment, such as 3d printers, CNC machines, etc. It only
copies files that match these file formats.

No external dependencies required.

specific.py
-----------

As the name suggests, this script copies only specific file formats according
to the configuration provided by the user.

No external dependencies required.
