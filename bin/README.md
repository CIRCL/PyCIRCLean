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

filecheck.py
------------

This is the script used by the [CIRCLean](https://github.com/CIRCL/Circlean)
USB key sanitizer. It is designed to handle a range of file types, and will
mark them as dangerous if they meet certain criteria.

Requirements by type of document:
* Microsoft office: oletools, olefile
* OOXML: officedissector
* PDF: pdfid
* Archives: p7zip-full, p7zip-rar
* Metadata: exifread
* Images: pillow

Note: pdfid is a not installable with pip. It must be downloaded and installed
manually in the directory where filecheck will be run.

```
    sudo apt-get install p7zip-full p7zip-rar libxml2-dev libxslt1-dev
    pip install lxml oletools olefile pillow exifread
    pip install git+https://github.com/Rafiot/officedissector.git
    # installing pdfid manually
    wget https://didierstevens.com/files/software/pdfid_v0_2_1.zip
    unzip pdfid_v0_2_1.zip
```

generic.py
----------

This is a script used by an older version of CIRCLean. It has more dependencies
than filecheck.py and they are more complicated to install.

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

This script has a list of file formats for various brands of industrial
manufacturing equipment, such as 3d printers, CNC machines, etc. It only
copies files that match these file formats.

No external dependencies required.

specific.py
-----------

As the name suggests, this script copies only specific file formats according
to the configuration provided by the user.

No external dependencies required.
