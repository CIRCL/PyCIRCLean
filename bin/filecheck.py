#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shlex
import subprocess
import argparse
import shutil

from kittengroomer import KittenGroomerBase, Logging
from analyse import Config, File




SEVENZ_PATH = '/usr/bin/7z'




class GroomerLogger(object):
    """Groomer logging interface."""

    def __init__(self, src_root_path, dst_root_path, debug=False):
        self._src_root_path = src_root_path
        self._dst_root_path = dst_root_path
        self._log_dir_path = self._make_log_dir(dst_root_path)
        self.log_path = os.path.join(self._log_dir_path, 'circlean_log.txt')
        self._add_root_dir(src_root_path)
        if debug:
            self.log_debug_err = os.path.join(self._log_dir_path, 'debug_stderr.log')
            self.log_debug_out = os.path.join(self._log_dir_path, 'debug_stdout.log')
        else:
            self.log_debug_err = os.devnull
            self.log_debug_out = os.devnull

    def _make_log_dir(self, root_dir_path):
        """Make the directory in the dest dir that will hold the logs"""
        log_dir_path = os.path.join(root_dir_path, 'logs')
        if os.path.exists(log_dir_path):
            shutil.rmtree(log_dir_path)
        os.makedirs(log_dir_path)
        return log_dir_path

    def _add_root_dir(self, root_path):
        dirname = os.path.split(root_path)[1] + '/'
        with open(self.log_path, mode='ab') as lf:
            lf.write(bytes(dirname, 'utf-8'))
            lf.write(b'\n')

    def add_file(self, file_path, file_props, in_tempdir=False):
        """Add a file to the log. Takes a dict of file properties."""
        # TODO: fix var names in this method
        # TODO: handle symlinks better: symlink_string = '{}+-- {}\t- Symbolic link to {}\n'.format(padding, f, os.readlink(curpath))
        props = file_props
        depth = self._get_path_depth(file_path)
        description_string = ', '.join(props['description_string'])
        file_hash = Logging.computehash(file_path)[:6]
        if props['safety_category'] is None:
            descr_cat = "Normal"
        else:
            descr_cat = props['safety_category'].capitalize()
        size = self._convert_size(props['file_size'])
        file_template = "+- {name} ({sha_hash}): {size}, {mt}/{st}. {desc}: {desc_str}"
        file_string = file_template.format(
            name=props['filename'],
            sha_hash=file_hash,
            size=size,
            mt=props['maintype'],
            st=props['subtype'],
            desc=descr_cat,
            desc_str=description_string,
            # errs=''  # TODO: add errors in human readable form here
        )
        if in_tempdir:
            depth -= 1
        self._write_line_to_log(file_string, depth)
        
    def _convert_size(self, size, precision=2):
        suffixes=['B','KB','MB','GB']
        suffixIndex = 0
        while size > 1024 and suffixIndex < 4:
            suffixIndex += 1
            size = size/1024.0
        return "%.*f%s"%(precision, size, suffixes[suffixIndex])

    def add_dir(self, dir_path):
        path_depth = self._get_path_depth(dir_path)
        dirname = os.path.split(dir_path)[1] + '/'
        log_line = '+- ' + dirname
        self._write_line_to_log(log_line, path_depth)

    def _get_path_depth(self, path):
        if self._dst_root_path in path:
            base_path = self._dst_root_path
        elif self._src_root_path in path:
            base_path = self._src_root_path
        relpath = os.path.relpath(path, base_path)
        path_depth = relpath.count(os.path.sep)
        return path_depth

    def _write_line_to_log(self, line, indentation_depth):
        padding = b'   '
        padding += b'|  ' * indentation_depth
        line_bytes = os.fsencode(line)
        with open(self.log_path, mode='ab') as lf:
            lf.write(padding)
            lf.write(line_bytes)
            lf.write(b'\n')


class KittenGroomerFileCheck(KittenGroomerBase):

    def __init__(self, root_src, root_dst, max_recursive_depth=2, debug=False):
        super(KittenGroomerFileCheck, self).__init__(root_src, root_dst)
        self.recursive_archive_depth = 0
        self.max_recursive_depth = max_recursive_depth
        self.cur_file = None
        self.logger = GroomerLogger(root_src, root_dst, debug)

    def process_dir(self, src_dir, dst_dir):
        """Process a directory on the source key."""
        for srcpath in self.list_files_dirs(src_dir):
            if os.path.isdir(srcpath):
                self.logger.add_dir(srcpath)
            else:
                dstpath = os.path.join(dst_dir, os.path.basename(srcpath))
                self.cur_file = File(srcpath, dstpath, self.logger)
                self.process_file(self.cur_file)

    def process_file(self, file):
        """
        Process an individual file.

        Check the file, handle archives using self.process_archive, copy
        the file to the destionation key, and clean up temporary directory.
        """
        file.check()
        if file.should_copy:
            file.safe_copy()
            file.set_property('copied', True)
        file.write_log()
        if file.is_recursive:
            self.process_archive(file)
        # TODO: Can probably handle cleaning up the tempdir better
        if hasattr(file, 'tempdir_path'):
            self.safe_rmtree(file.tempdir_path)

    def process_archive(self, file):
        """
        Unpack an archive using 7zip and process contents using process_dir.

        Should be given a Kittengroomer file object whose src_path points
        to an archive.
        """
        self.recursive_archive_depth += 1
        if self.recursive_archive_depth >= self.max_recursive_depth:
            file.make_dangerous('Archive bomb')
        else:
            tempdir_path = file.make_tempdir()
            # TODO: double check we are properly escaping file.src_path
            # otherwise we are running unsanitized user input directly in the shell
            command_str = '{} -p1 x "{}" -o"{}" -bd -aoa'
            unpack_command = command_str.format(SEVENZ_PATH,
                                                file.src_path, tempdir_path)
            self._run_process(unpack_command, Config.archive_timeout)
            file.write_log()
            self.process_dir(tempdir_path, file.dst_path)
            self.safe_rmtree(tempdir_path)
        self.recursive_archive_depth -= 1

    def _run_process(self, command_string, timeout=None):
        """Run command_string in a subprocess, wait until it finishes."""
        args = shlex.split(command_string)
        with open(self.logger.log_debug_err, 'ab') as stderr, open(self.logger.log_debug_out, 'ab') as stdout:
            try:
                subprocess.check_call(args, stdout=stdout, stderr=stderr, timeout=timeout)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                return
        return True

    def list_files_dirs(self, root_dir_path):
        queue = []
        for path in sorted(os.listdir(root_dir_path), key=lambda x: str.lower(x)):
            full_path = os.path.join(root_dir_path, path)
            if os.path.isdir(full_path):
                queue.append(full_path)
                queue += self.list_files_dirs(full_path)  # if path is a dir, recurse through its contents
            elif os.path.isfile(full_path):
                queue.append(full_path)
        return queue

    def run(self):
        self.process_dir(self.src_root_path, self.dst_root_path)


def main(kg_implementation, description):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.run()


if __name__ == '__main__':
    main(KittenGroomerFileCheck, 'File sanitizer used in CIRCLean. Renames potentially dangerous files.')
