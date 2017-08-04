#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Contains the base objects for use when creating a sanitizer using
PyCIRCLean. Subclass or import from FileBase/KittenGroomerBase and implement
your desired behavior.
"""


import os
import hashlib
import shutil
import argparse
import stat

import magic


class FileBase(object):
    """
    Base object for individual files in the source directory.

    Contains file attributes and various helper methods.
    """

    def __init__(self, src_path, dst_path):
        """
        Initialized with the source path and expected destination path.

        Create various properties and determine the file's mimetype.
        """
        self.src_path = src_path
        self.dst_dir = os.path.dirname(dst_path)
        self.filename = os.path.basename(src_path)
        self.size = self._get_size(src_path)
        self.is_dangerous = False
        self.copied = False
        self.symlink_path = None
        self._description_string = []  # array of descriptions to be joined
        self._errors = {}
        self._user_defined = {}
        self.should_copy = True
        self.mimetype = self._determine_mimetype(src_path)

    @property
    def dst_path(self):
        return os.path.join(self.dst_dir, self.filename)

    @property
    def extension(self):
        _, ext = os.path.splitext(self.filename)
        if ext == '':
            return None
        else:
            return ext.lower()

    @property
    def maintype(self):
        main, _ = self._split_mimetype(self.mimetype)
        return main

    @property
    def subtype(self):
        _, sub = self._split_mimetype(self.mimetype)
        return sub

    @property
    def has_mimetype(self):
        """True if file has a main and sub mimetype, else False."""
        if not self.maintype or not self.subtype:
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
    def is_symlink(self):
        """True if file is a symlink, else False."""
        if self.symlink_path is None:
            return False
        else:
            return True

    @property
    def description_string(self):
        if len(self._description_string) == 0:
            return 'No description'
        elif len(self._description_string) == 1:
            return self._description_string[0]
        else:
            ret_string = ', '.join(self._description_string)
            return ret_string.strip(', ')

    @description_string.setter
    def description_string(self, value):
        if hasattr(self, 'description_string'):
            if isinstance(value, str):
                if value not in self._description_string:
                    self._description_string.append(value)
            else:
                raise TypeError("Description_string can only include strings")
        else:
            self._description_string = value

    def set_property(self, prop_string, value):
        """
        Take a property and a value and add them to the file's stored props.

        If `prop_string` is part of the file property API, set it to `value`.
        Otherwise, add `prop_string`: `value` to `user_defined` properties.
        TODO: rewrite docstring
        """
        if hasattr(self, prop_string):
            setattr(self, prop_string, value)
        else:
            self._user_defined[prop_string] = value

    def get_property(self, prop_string):
        """
        Get the value for a property stored on the file.

        Returns `None` if `prop_string` cannot be found on the file.
        """
        try:
            return getattr(self, prop_string)
        except AttributeError:
            return self._user_defined.get(prop_string, None)

    def get_all_props(self):
        """Return a dict containing all stored properties of this file."""
        # Maybe move this onto the logger? I think that makes more sense
        props_dict = {
            'filepath': self.src_path,
            'filename': self.filename,
            'file_size': self.size,
            'mimetype': self.mimetype,
            'maintype': self.maintype,
            'subtype': self.subtype,
            'extension': self.extension,
            'is_dangerous': self.is_dangerous,
            'is_symlink': self.is_symlink,
            'symlink_path': self.symlink_path,
            'copied': self.copied,
            'description_string': self.description_string,
            'errors': self._errors,
            'user_defined': self._user_defined
        }
        return props_dict

    def add_error(self, error, info_string):
        """Add an `error`: `info_string` pair to the file."""
        self._errors.update({error: info_string})

    def add_description(self, description_string):
        """
        Add a description string to the file.

        If `description_string` is already present, will prevent duplicates.
        """
        self.set_property('description_string', description_string)

    def make_dangerous(self, reason_string=None):
        """
        Mark file as dangerous.

        Prepend and append DANGEROUS to the destination file name
        to help prevent double-click of death.
        """
        if not self.is_dangerous:
            self.set_property('is_dangerous', True)
            self.filename = 'DANGEROUS_{}_DANGEROUS'.format(self.filename)
        if reason_string:
            self.add_description(reason_string)

    def safe_copy(self, src=None, dst=None):
        """
        Copy file and create destination directories if needed.

        Sets all exec bits to '0'.
        """
        if src is None:
            src = self.src_path
        if dst is None:
            dst = self.dst_path
        try:
            os.makedirs(self.dst_dir, exist_ok=True)
            shutil.copy(src, dst)
            current_perms = self._get_file_permissions(dst)
            only_exec_bits = 0o0111
            perms_no_exec = current_perms & (~only_exec_bits)
            os.chmod(dst, perms_no_exec)
        except IOError as e:
            # Probably means we can't write in the dest dir
            self.add_error(e, '')

    def force_ext(self, extension):
        """If dst_path does not end in `extension`, append .ext to it."""
        new_ext = self._check_leading_dot(extension)
        if not self.filename.endswith(new_ext):
            # TODO: log that the extension was changed
            self.filename += new_ext
        if not self.get_property('extension') == new_ext:
            self.set_property('extension', new_ext)

    def create_metadata_file(self, extension):
        # TODO: this method name is confusing
        """
        Create a separate file to hold extracted metadata.

        The string `extension` will be used as the extension for the file.
        """
        ext = self._check_leading_dot(extension)
        try:
            # Prevent using the same path as another file from src_path
            if os.path.exists(self.src_path + ext):
                raise KittenGroomerError(
                    "Could not create metadata file for \"" +
                    self.filename +
                    "\": a file with that path exists.")
            else:
                os.makedirs(self.dst_dir, exist_ok=True)
                # TODO: shouldn't mutate state and also return something
                self.metadata_file_path = self.dst_path + ext
                return self.metadata_file_path
        # TODO: can probably let this exception bubble up
        except KittenGroomerError as e:
            self.add_error(e, '')
            return False

    def _check_leading_dot(self, ext):
        # TODO: this method name is confusing
        if len(ext) > 0:
            if not ext.startswith('.'):
                return '.' + ext
        return ext

    def _determine_mimetype(self, file_path):
        if os.path.islink(file_path):
            # libmagic will throw an IOError on a broken symlink
            mimetype = 'inode/symlink'
            self.set_property('symlink_path', os.readlink(file_path))
        else:
            try:
                mt = magic.from_file(file_path, mime=True)
                # libmagic will always return something, even if it's just 'data'
            except UnicodeEncodeError as e:
                raise UnicodeEncodeError
                self.add_error(e, '')
                mt = None
            try:
                mimetype = mt.decode("utf-8")
            except:
                # FIXME: what should the exception be here if mimetype isn't utf-8?
                mimetype = mt
        return mimetype

    def _split_mimetype(self, mimetype):
        if mimetype and '/' in mimetype:
            main_type, sub_type = mimetype.split('/')
        else:
            main_type, sub_type = None, None
        return main_type, sub_type

    def _get_size(self, file_path):
        """Filesize in bytes as an int, 0 if file does not exist."""
        try:
            size = os.path.getsize(file_path)
        except FileNotFoundError:
            size = 0
        return size

    def _remove_exec_bit(self, file_path):
        current_perms = self._get_file_permissions(file_path)
        perms_no_exec = current_perms & (~stat.S_IEXEC)
        os.chmod(file_path, perms_no_exec)

    def _get_file_permissions(self, file_path):
        full_mode = os.stat(file_path, follow_symlinks=False).st_mode
        return stat.S_IMODE(full_mode)


class Logging(object):

    @staticmethod
    def computehash(path):
        """Return the sha256 hash of a file at a given path."""
        s = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                buf = f.read(0x100000)
                if not buf:
                    break
                s.update(buf)
        return s.hexdigest()


class KittenGroomerBase(object):
    """Base object responsible for copy/sanitization process."""

    def __init__(self, src_root_path, dst_root_path):
        """Initialized with path to source and dest directories."""
        self.src_root_path = os.path.abspath(src_root_path)
        self.dst_root_path = os.path.abspath(dst_root_path)

    def safe_rmtree(self, directory_path):
        """Remove a directory tree if it exists."""
        if os.path.exists(directory_path):
            shutil.rmtree(directory_path)

    def safe_remove(self, file_path):
        """Remove file at file_path if it exists."""
        if os.path.exists(file_path):
            os.remove(file_path)

    def safe_mkdir(self, directory_path):
        """Make a directory if it does not exist."""
        if not os.path.exists(directory_path):
            os.makedirs(directory_path)

    def list_all_files(self, directory_path):
        """Generator yielding path to all of the files in a directory tree."""
        for root, dirs, files in os.walk(directory_path):
            # files is a list anyway so we don't get much from using a generator here
            for filename in files:
                filepath = os.path.join(root, filename)
                yield filepath

    #######################

    def processdir(self, src_dir, dst_dir):
        """Implement this function to define file processing behavior."""
        raise ImplementationRequired('Please implement processdir.')


class KittenGroomerError(Exception):
    """Base KittenGroomer exception handler."""

    def __init__(self, message):
        super(KittenGroomerError, self).__init__(message)
        self.message = message


class ImplementationRequired(KittenGroomerError):
    """Implementation required error."""
    pass


def main(kg_implementation, description='Call a KittenGroomer implementation to process files present in the source directory and copy them to the destination directory.'):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.processdir()
