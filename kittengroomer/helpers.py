#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Contains the base objects for use when creating a sanitizer using
PyCIRCLean. Subclass FileBase and KittenGroomerBase to implement your
desired behavior.
"""


import os
import hashlib
import shutil
import argparse

import magic
import twiggy


class KittenGroomerError(Exception):
    """Base KittenGroomer exception handler."""

    def __init__(self, message):
        super(KittenGroomerError, self).__init__(message)
        self.message = message


class ImplementationRequired(KittenGroomerError):
    """Implementation required error."""
    pass


class FileBase(object):
    """
    Base object for individual files in the source directory.

    Contains file attributes and various helper methods.
    """

    def __init__(self, src_path, dst_path, logger=None):
        """
        Initialized with the source path and expected destination path.

        self.logger should be a logging object with an add_file method.
        Create various properties and determine the file's mimetype.
        """
        self.src_path = src_path
        self.dst_path = dst_path
        self.filename = os.path.basename(self.src_path)
        self.logger = logger
        self._file_props = {
            'filepath': self.src_path,
            'filename': self.filename,
            'file_size': self.size,
            'maintype': None,
            'subtype': None,
            'extension': None,
            'safety_category': None,
            'symlink': False,
            'copied': False,
            'file_string_set': set(),
            'errors': {},
            'user_defined': {}
        }
        self.extension = self._determine_extension()
        self.set_property('extension', self.extension)
        self.mimetype = self._determine_mimetype()
        self.should_copy = True
        self.main_type = None
        self.sub_type = None
        if self.mimetype:
            self.main_type, self.sub_type = self._split_subtypes(self.mimetype)
            if self.main_type:
                self.set_property('maintype', self.main_type)
            if self.sub_type:
                self.set_property('subtype', self.sub_type)

    def _determine_extension(self):
        _, ext = os.path.splitext(self.src_path)
        ext = ext.lower()
        if ext == '':
            ext = None
        return ext

    def _determine_mimetype(self):
        if os.path.islink(self.src_path):
            # magic will throw an IOError on a broken symlink
            mimetype = 'inode/symlink'
            self.set_property('symlink', os.readlink(self.src_path))
        else:
            try:
                mt = magic.from_file(self.src_path, mime=True)
                # Note: magic will always return something, even if it's just 'data'
            except UnicodeEncodeError as e:
                # FIXME: The encoding of the file is broken (possibly UTF-16)
                # Note: one of the Travis files will trigger this exception
                self.add_error(e, '')
                mt = None
            try:
                mimetype = mt.decode("utf-8")
            except:
                mimetype = mt
        return mimetype

    def _split_subtypes(self, mimetype):
        if '/' in mimetype:
            main_type, sub_type = mimetype.split('/')
        else:
            main_type, sub_type = None, None
        return main_type, sub_type

    @property
    def size(self):
        """Filesize in bytes as an int, 0 if file does not exist."""
        try:
            size = os.path.getsize(self.src_path)
        except FileNotFoundError:
            size = 0
        return size

    @property
    def has_mimetype(self):
        """True if file has a main and sub mimetype, else False."""
        # TODO: broken mimetype checks should be done somewhere else.
        # Should the check be by default or should we let the API consumer write it?
        if not self.main_type or not self.sub_type:
            return False
        else:
            return True

    @property
    def has_extension(self):
        """True if self.extension is set, else False."""
        if self.extension is None:
            return False
        else:
            return True

    @property
    def is_dangerous(self):
        """True if file has been marked 'dangerous', else False."""
        return self._file_props['safety_category'] is 'dangerous'

    @property
    def is_unknown(self):
        """True if file has been marked 'unknown', else False."""
        return self._file_props['safety_category'] is 'unknown'

    @property
    def is_binary(self):
        """True if file has been marked 'binary', else False."""
        return self._file_props['safety_category'] is 'binary'

    @property
    def is_symlink(self):
        """True  if file is a symlink, else False."""
        if self._file_props['symlink'] is False:
            return False
        else:
            return True

    def set_property(self, prop_string, value):
        """
        Take a property and a value and add them to self._file_props.

        If prop_string is already in _file_props, set prop_string to value.
        If prop_string not in _file_props, set prop_string to value in
        _file_props['user_defined'].
        """
        if prop_string in self._file_props.keys():
            self._file_props[prop_string] = value
        else:
            self._file_props['user_defined'][prop_string] = value

    def get_property(self, file_prop):
        """Get the value for a property in _file_props."""
        # TODO: could probably be refactored
        if file_prop in self._file_props:
            return self._file_props[file_prop]
        elif file_prop in self._file_props['user_defined']:
            return self._file_props['user_defined'][file_prop]
        else:
            return None

    def add_error(self, error, info):
        """Add an error: info pair to _file_props['errors']."""
        self._file_props['errors'].update({error: info})

    def add_file_string(self, file_string):
        """Add a file descriptor string to _file_props."""
        self._file_props['file_string_set'].add(file_string)

    def make_dangerous(self, reason_string=None):
        """
        Mark file as dangerous.

        Prepend and append DANGEROUS to the destination file name
        to help prevent double-click of death.
        """
        if self.is_dangerous:
            return
        self.set_property('safety_category', 'dangerous')
        # LOG: store reason string somewhere and do something with it
        path, filename = os.path.split(self.dst_path)
        self.dst_path = os.path.join(path, 'DANGEROUS_{}_DANGEROUS'.format(filename))

    def make_unknown(self):
        """Mark file as an unknown type and prepend UNKNOWN to filename."""
        if self.is_dangerous or self.is_binary:
            return
        self.set_property('safety_category', 'unknown')
        path, filename = os.path.split(self.dst_path)
        self.dst_path = os.path.join(path, 'UNKNOWN_{}'.format(filename))

    def make_binary(self):
        """Mark file as a binary and append .bin to filename."""
        if self.is_dangerous:
            return
        self.set_property('safety_category', 'binary')
        path, filename = os.path.split(self.dst_path)
        self.dst_path = os.path.join(path, '{}.bin'.format(filename))

    def safe_copy(self, src=None, dst=None):
        """Copy file and create destination directories if needed."""
        if src is None:
            src = self.src_path
        if dst is None:
            dst = self.dst_path
        try:
            dst_path, filename = os.path.split(dst)
            if not os.path.exists(dst_path):
                os.makedirs(dst_path)
            shutil.copy(src, dst)
        except Exception as e:
            self.add_error(e, '')

    def force_ext(self, ext):
        """If dst_path does not end in ext, change it and edit _file_props."""
        if not self.dst_path.endswith(ext):
            self.set_property('force_ext', True)
            self.dst_path += ext
        if not self._file_props['extension'] == ext:
            self.set_property('extension', ext)

    def create_metadata_file(self, ext):
        """Create a separate file to hold metadata from this file."""
        try:
            # make sure we aren't overwriting anything
            if os.path.exists(self.src_path + ext):
                raise KittenGroomerError("Cannot create split metadata file for \"" +
                                         self.dst_path + "\", type '" +
                                         ext + "': File exists.")
            else:
                dst_dir_path, filename = os.path.split(self.dst_path)
                if not os.path.exists(dst_dir_path):
                    os.makedirs(dst_dir_path)
                # TODO: Check extension for leading "."
                self.metadata_file_path = self.dst_path + ext
                return self.metadata_file_path
        except KittenGroomerError as e:
            self.add_error(e, '')
            return False

    def write_log(self):
        """Write logs from file to self.logger."""
        file_log = self.logger.add_file(self)
        file_log.fields(**self._file_props)


class GroomerLogger(object):
    """Groomer logging interface."""

    def __init__(self, root_dir_path, debug=False):
        self.root_dir = root_dir_path
        self.log_dir_path = os.path.join(root_dir_path, 'logs')
        if os.path.exists(self.log_dir_path):
            shutil.rmtree(self.log_dir_path)
        os.makedirs(self.log_dir_path)
        self.log_processing = os.path.join(self.log_dir_path, 'processing.log')
        self.log_content = os.path.join(self.log_dir_path, 'content.log')
        twiggy.quick_setup(file=self.log_processing)
        self.log = twiggy.log.name('files')
        if debug:
            self.log_debug_err = os.path.join(self.log_dir_path, 'debug_stderr.log')
            self.log_debug_out = os.path.join(self.log_dir_path, 'debug_stdout.log')
        else:
            self.log_debug_err = os.devnull
            self.log_debug_out = os.devnull

    def tree(self, base_dir, padding='   '):
        """Write a graphical tree to the log for `base_dir`."""
        with open(self.log_content, 'ab') as lf:
            lf.write(bytes('#' * 80 + '\n', 'UTF-8'))
            lf.write(bytes('{}+- {}/\n'.format(padding, os.path.basename(os.path.abspath(base_dir)).encode()), 'utf8'))
            padding += '|  '
            files = sorted(os.listdir(base_dir))
            for f in files:
                curpath = os.path.join(base_dir, f)
                if os.path.islink(curpath):
                    lf.write('{}+-- {}\t- Symbolic link to {}\n'.format(padding, f, os.readlink(curpath)).encode(errors='ignore'))
                elif os.path.isdir(curpath):
                    self.tree(curpath, padding)
                elif os.path.isfile(curpath):
                    lf.write('{}+-- {}\t- {}\n'.format(padding, f, self._computehash(curpath)).encode(errors='ignore'))

    def _computehash(self, path):
        """Return a sha256 hash of a file at a given path."""
        s = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                buf = f.read(0x100000)
                if not buf:
                    break
                s.update(buf)
        return s.hexdigest()

    def add_file(self, file):
        """Add a file to the log."""
        return self.log.name('file.src_path')


class KittenGroomerBase(object):
    """Base object responsible for copy/sanitization process."""

    def __init__(self, root_src, root_dst, debug=False):
        """Initialized with path to source and dest directories."""
        self.src_root_dir = root_src
        self.dst_root_dir = root_dst
        self.debug = debug
        self.cur_file = None
        self.logger = GroomerLogger(self.dst_root_dir, debug)

    def safe_rmtree(self, directory):
        """Remove a directory tree if it exists."""
        if os.path.exists(directory):
            shutil.rmtree(directory)

    def safe_remove(self, filepath):
        """Remove a file if it exists."""
        if os.path.exists(filepath):
            os.remove(filepath)

    def safe_mkdir(self, directory):
        """Make a directory if it does not exist."""
        if not os.path.exists(directory):
            os.makedirs(directory)

    def list_all_files(self, directory):
        """Generator yielding path to all of the files in a directory tree."""
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                yield filepath

    #######################

    # TODO: feels like this function doesn't need to exist if we move main()
    def processdir(self, src_dir, dst_dir):
        """Implement this function to define file processing behavior."""
        raise ImplementationRequired('Please implement processdir.')


# TODO: Maybe this shouldn't exist? It should probably get moved to filecheck since this isn't really API code
def main(kg_implementation, description='Call a KittenGroomer implementation to process files present in the source directory and copy them to the destination directory.'):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.processdir()
