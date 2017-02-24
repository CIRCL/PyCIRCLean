#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from kittengroomer import FileBase, KittenGroomerBase, main


# Extension
configfiles = {'.conf': 'text/plain'}


class FileSpec(FileBase):

    def __init__(self, src_path, dst_path):
        ''' Init file object, set the extension '''
        super(FileSpec, self).__init__(src_path, dst_path)

        if not self.has_mimetype():
            self.make_dangerous()

        if not self.has_extension():
            self.make_dangerous()


class KittenGroomerSpec(KittenGroomerBase):

    def __init__(self, root_src=None, root_dst=None, debug=False):
        '''
            Initialize the basics of the copy
        '''
        if root_src is None:
            root_src = os.path.join(os.sep, 'media', 'src')
        if root_dst is None:
            root_dst = os.path.join(os.sep, 'media', 'dst')
        super(KittenGroomerSpec, self).__init__(root_src, root_dst, debug)
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
        for srcpath in self.list_all_files(self.src_root_dir):
            valid = True
            self.log_name.info('Processing {}', srcpath.replace(self.src_root_dir + '/', ''))
            self.cur_file = FileSpec(srcpath, srcpath.replace(self.src_root_dir, self.dst_root_dir))
            if self.cur_file.is_dangerous():
                valid = False
                error.append(self.cur_file)
            else:
                expected_mime = self.valid_files.get(self.cur_file.extension)
                compare_ext = ''
                compare_mime = ''
                if expected_mime is None:
                    # Unexpected extension => disallowed
                    valid = False
                    compare_ext = 'Extension: {} - Expected: {}'.format(self.cur_file.extension, ', '.join(self.valid_files.keys()))
                elif self.cur_file.mimetype != expected_mime:
                    # Unexpected mimetype => dissalowed
                    valid = False
                    compare_mime = 'Mime: {} - Expected: {}'.format(self.cur_file.mimetype, expected_mime)

                if valid:
                    to_copy.append(self.cur_file)
                    self.cur_file.log_string = 'Extension: {} - MimeType: {}'.format(self.cur_file.extension, self.cur_file.mimetype)
                else:
                    error.append(self.cur_file)
                    if compare_ext:
                        self.cur_file.log_string = compare_ext
                    else:
                        self.cur_file.log_string = compare_mime
            self.cur_file.add_log_details('valid', valid)

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
