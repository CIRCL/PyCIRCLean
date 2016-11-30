Example scripts
===============

These are a series of example scripts designed to demonstrate PyCIRCLean's capabilities. Feel free to
adapt or modify any of them to suit your requirements. In order to use any of these scripts, you will need to
install the PyCIRCLean dependencies (preferably in a virtualenv):

```
    pip install git+https://github.com/ahupp/python-magic.git   # we cannot use the PyPi package for now due to a bug
    python setup.py install     # from the root of the repository
```

Requirements per script
=======================


filecheck.py
------------

*WARNING*: Only works with Python 2.7 (oletools and olefile aren't ported to Python3 for now)

Requirements by type of document:
* Microsoft office: oletools, olefile
* OOXML: officedissector
* PDF: pdfid
* Archives: p7zip-full, p7zip-rar


```
    sudo apt-get install p7zip-full p7zip-rar libxml2-dev libxslt1-dev
    pip install lxml officedissector git+https://github.com/ahupp/python-magic.git oletools olefile
    pip install git+https://github.com/Rafiot/officedissector.git
    # pdfid is not a package, installing manually
    wget https://didierstevens.com/files/software/pdfid_v0_2_1.zip
    unzip pdfid_v0_2_1.zip
    python setup.py -q install
```

generic.py
----------

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

No external dependencies required.

specific.py
-----------

No external dependencies required.
