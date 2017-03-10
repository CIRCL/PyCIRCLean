filecheck.py
============

This is the script used by the [CIRCLean](https://github.com/CIRCL/Circlean)
USB key sanitizer. It is designed to handle a range of file types, and will
mark them as dangerous if they meet certain criteria.

Before installing the filecheck.py depenencies, make sure to install the PyCIRCLean
dependencies:

```
    pip install .
```

Dependencies by type of document:
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
