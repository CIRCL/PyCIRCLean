[![Build Status](https://travis-ci.org/CIRCL/PyCIRCLean.svg?branch=master)](https://travis-ci.org/CIRCL/PyCIRCLean)
[![codecov.io](https://codecov.io/github/CIRCL/PyCIRCLean/coverage.svg?branch=master)](https://codecov.io/github/CIRCL/PyCIRCLean?branch=master)

# PyCIRCLean

PyCIRCLean is the core Python code used by [CIRCLean](https://github.com/CIRCL/Circlean/), an open-source
USB key and document sanitizer created by [CIRCL](https://www.circl.lu/). This module has been separated from the
device-specific scripts and can be used for dedicated security applications to sanitize documents from hostile environments
to trusted environments. PyCIRCLean is currently Python 3.3+ compatible. Some of its dependencies are Linux-only, and
running the tests will require access to a Linux box or VM.

# Installation

~~~
python setup.py install
~~~

OR

~~~
pip install .
~~~

# How to use PyCIRCLean

PyCIRCLean is a simple Python library to handle file checking and sanitization.
PyCIRCLean is designed to be extended to cover specific checking
and sanitization workflows in different organizations such as industrial
environments or restricted/classified ICT environments. A series of practical examples utilizing PyCIRCLean can be found
in the [./examples](./examples) directory. Note: for commits beyond version 2.2.0 these
examples are out of date and not guaranteed to work with the PyCIRCLean API. Please check [helpers.py](./kittengroomer/
helpers.py) or [filecheck.py](./bin/filecheck.py) to see the new API interface.

The following simple example using PyCIRCLean will only copy files with a .conf extension matching the 'text/plain'
mimetype. If any other file is found in the source directory, the files won't be copied to the destination directory.

~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import magic

from kittengroomer import FileBase, KittenGroomerBase, main


# Extension
class Config:
    configfiles = {'.conf': 'text/plain'}


class FileSpec(FileBase):

    def __init__(self, src_path, dst_path):
        """Init file object, set the extension."""
        super(FileSpec, self).__init__(src_path, dst_path)
        self.valid_files = {}
        # The initial version will only accept the file extensions/mimetypes listed here.
        self.valid_files.update(Config.configfiles)

    def check(self):
        valid = True
        expected_mime = self.valid_files.get(self.extension)
        if expected_mime is None:
            # Unexpected extension => disallowed
            valid = False
            compare_ext = 'Extension: {} - Expected: {}'.format(self.cur_file.extension, ', '.join(self.valid_files.keys()))
        elif self.mimetype != expected_mime:
            # Unexpected mimetype => disallowed
            valid = False
            compare_mime = 'Mime: {} - Expected: {}'.format(self.cur_file.mimetype, expected_mime)
        else:
            self.should_copy = False
        if self.should_copy:
            self.safe_copy()


class KittenGroomerSpec(KittenGroomerBase):

    def __init__(self, root_src=None, root_dst=None):
        """Initialize the basics of the copy."""
        if root_src is None:
            root_src = os.path.join(os.sep, 'media', 'src')
        if root_dst is None:
            root_dst = os.path.join(os.sep, 'media', 'dst')
        super(KittenGroomerSpec, self).__init__(root_src, root_dst)

    def processdir(self):
        """Main function doing the processing."""
        to_copy = []
        error = []
        for srcpath in self.list_all_files(self.src_root_dir):
            dstpath = srcpath.replace(self.src_root_dir, self.dst_root_dir)
            cur_file = FileSpec(srcpath, dstpath)
            cur_file.check()


if __name__ == '__main__':
    main(KittenGroomerSpec, ' Only copy some files, returns an error is anything else is found')

~~~

# How to contribute

We welcome contributions (including bug fixes and new example file processing
workflows) via pull requests. We are particularly interested in any new workflows
that can be used to improve security in different organizations. If you see any
potential enhancements required to support your sanitization workflow, please feel
free to open an issue. Read [CONTRIBUTING.md](/CONTRIBUTING.md) for more
information.


# License

~~~
Copyright (C) 2013-2015 Raphaël Vinot
Copyright (C) 2013-2015 CIRCL - Computer Incident Response Center Luxembourg (℅ smile gie)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
~~~
