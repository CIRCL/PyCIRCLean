[![Build Status](https://travis-ci.org/CIRCL/PyCIRCLean.svg?branch=master)](https://travis-ci.org/CIRCL/PyCIRCLean)

# PyCIRCLean

PyCIRCLean is the Python code used by [CIRCLean](https://www.circl.lu/projects/CIRCLean/), the USB key and document sanitizer. The code
has been separated from the devices as PyCIRCLean software can be used for dedicated security applications to sanitize documents
from hostile environments to trusted environments.

# Installation

~~~
python setup.py build
python setup.py install
~~~

# How to use PyCIRCLean

PyCIRCLean is a simple Python library to handle file checking and sanitization. PyCIRCLean purpose is to have a simple library that can be
overloaded to cover specific checking and sanitization workflows in different organizations like industrial environment or restricted/classified ICT environment. A series of practical example are in the [./bin](./bin) directory.

The following simple example using PyCIRCLean will only copy files with .conf extension matching the 'text/plain' MIME type. If any other file is found on the original USB key (source directory), the files won't be copied to the destination directory.

~~~python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import magic

from kittengroomer import FileBase, KittenGroomerBase, main


# Extension
configfiles = {'.conf': 'text/plain'}


class FileSpec(FileBase):

    def __init__(self, src_path, dst_path):
        ''' Init file object, set the extension '''
        super(FileSpec, self).__init__(src_path, dst_path)
        a, self.extension = os.path.splitext(self.src_path)
        self.mimetype = magic.from_file(self.src_path, mime=True).decode("utf-8")


class KittenGroomerSpec(KittenGroomerBase):

    def __init__(self, root_src=None, root_dst=None):
        '''
            Initialize the basics of the copy
        '''
        if root_src is None:
            root_src = os.path.join(os.sep, 'media', 'src')
        if root_dst is None:
            root_dst = os.path.join(os.sep, 'media', 'dst')
        super(KittenGroomerSpec, self).__init__(root_src, root_dst)
        self.valid_files = {}

        # The initial version will only accept the file extensions/mimetypes listed here.
        self.valid_files.update(configfiles)

    def _print_log(self):
        '''
            Print the logs related to the current file being processed
        '''
        tmp_log = self.log_name.fields(**self.cur_file.log_details)
        if not self.cur_file.log_details.get('valid'):
            tmp_log.warning(self.cur_file.log_string)
        else:
            tmp_log.debug(self.cur_file.log_string)

    def processdir(self):
        '''
            Main function doing the processing
        '''
        to_copy = []
        error = []
        for srcpath in self._list_all_files(self.src_root_dir):
            valid = True
            self.log_name.info('Processing {}', srcpath.replace(self.src_root_dir + '/', ''))
            self.cur_file = FileSpec(srcpath, srcpath.replace(self.src_root_dir, self.dst_root_dir))
            expected_mime = self.valid_files.get(self.cur_file.extension)
            if expected_mime is None:
                # Unexpected extension => disallowed
                valid = False
                compare_ext = 'Extension: {} - Expected: {}'.format(self.cur_file.extension, ', '.join(self.valid_files.keys()))
            elif self.cur_file.mimetype != expected_mime:
                # Unexpected mimetype => dissalowed
                valid = False
                compare_mime = 'Mime: {} - Expected: {}'.format(self.cur_file.mimetype, expected_mime)
            self.cur_file.add_log_details('valid', valid)
            if valid:
                to_copy.append(self.cur_file)
                self.cur_file.log_string = 'Extension: {} - MimeType: {}'.format(self.cur_file.extension, self.cur_file.mimetype)
            else:
                error.append(self.cur_file)
                if compare_ext is not None:
                    self.cur_file.log_string = compare_ext
                else:
                    self.cur_file.log_string = compare_mime
        if len(error) > 0:
            for f in error + to_copy:
                self.cur_file = f
                self._print_log()
        else:
            for f in to_copy:
                self.cur_file = f
                self._safe_copy()
                self._print_log()


if __name__ == '__main__':
    main(KittenGroomerSpec, ' Only copy some files, returns an error is anything else is found')
    exit(0)
~~~

# How to contribute

We welcome contributions (including bug fixes, new code workflows) via pull requests. We are interested in any new workflows
that can be used to improve security in different organizations. If you see any potential enhancement required to support
your sanitization workflow, feel free to open an issue.


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
