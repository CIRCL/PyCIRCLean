#!/usr/bin/env python3
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
import traceback
from pathlib import Path
from typing import Union, Optional, List, Dict, Any, Tuple, Iterator

import magic  # type: ignore


class FileBase(object):
    """
    Base object for individual files in the source directory.

    Contains file attributes and various helper methods.
    """

    def __init__(self, src_path: Path, dst_path: Path):
        """
        Initialized with the source path and expected destination path.

        Create various properties and determine the file's mimetype.
        """
        self.src_path: Path = src_path
        self.dst_dir: Path = dst_path.parent
        self.filename: str = src_path.name
        self.size: int = self._get_size(src_path)
        self.is_dangerous: bool = False
        self.copied: bool = False
        self.symlink_path = None
        self._description_string: List[str] = []  # array of descriptions to be joined
        self._errors: Dict[Exception, str] = {}
        self._user_defined: Dict[str, str] = {}
        self.should_copy: bool = True
        self.mimetype = self._determine_mimetype(str(src_path))

    @property
    def dst_path(self) -> Path:
        return self.dst_dir / self.filename

    @property
    def extension(self) -> Union[None, str]:
        ext = self.src_path.suffix
        if ext == '':
            return None
        else:
            return ext.lower()

    @property
    def maintype(self) -> Optional[str]:
        main, _ = self._split_mimetype(self.mimetype)
        return main

    @property
    def subtype(self) -> Optional[str]:
        _, sub = self._split_mimetype(self.mimetype)
        return sub

    @property
    def has_mimetype(self) -> bool:
        """True if file has a main and sub mimetype, else False."""
        if not self.maintype or not self.subtype:
            return False
        else:
            return True

    @property
    def has_extension(self) -> bool:
        """True if self.extension is set, else False."""
        if self.extension is None:
            return False
        else:
            return True

    @property
    def is_symlink(self) -> bool:
        """True if file is a symlink, else False."""
        if self.symlink_path is None:
            return False
        else:
            return True

    @property
    def description_string(self) -> str:
        if len(self._description_string) == 0:
            return 'No description'
        elif len(self._description_string) == 1:
            return self._description_string[0]
        else:
            ret_string = ', '.join(self._description_string)
            return ret_string.strip(', ')  # NOTE: why strip?

    @description_string.setter
    def description_string(self, value: str):
        if not isinstance(value, str):
            raise TypeError(f"value ({value}) must be a 'str' and not a {type(value)}")
        if value not in self._description_string:
            self._description_string.append(value)

    def set_property(self, prop_string: str, value: Any):
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

    def get_property(self, prop_string: str) -> Any:
        """
        Get the value for a property stored on the file.

        Returns `None` if `prop_string` cannot be found on the file.
        """
        try:
            return getattr(self, prop_string)
        except AttributeError:
            return self._user_defined.get(prop_string, None)

    def get_all_props(self) -> dict:
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

    def add_error(self, error: Exception, info_string: str):
        """Add an `error`: `info_string` pair to the file."""
        self._errors.update({error: info_string})

    def add_description(self, description_string: str):
        """
        Add a description string to the file.

        If `description_string` is already present, will prevent duplicates.
        """
        self.set_property('description_string', description_string)

    def make_dangerous(self, reason_string: Optional[str]=None):
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

    def safe_copy(self):
        """
        Copy file and create destination directories if needed.

        Sets all exec bits to '0'.
        """
        src = self.src_path
        dst = self.dst_path
        try:
            self.dst_dir.mkdir(exist_ok=True, parents=True)
            shutil.copy(src, dst)
            current_perms = self._get_file_permissions(dst)
            only_exec_bits = 0o0111
            perms_no_exec = current_perms & (~only_exec_bits)
            dst.chmod(perms_no_exec)
            return True
        except IOError as e:
            # Probably means we can't write in the dest dir
            self.add_error(e, '')
            traceback.print_exc()
            return False

    def force_ext(self, extension: str):
        """If dst_path does not end in `extension`, append .ext to it."""
        new_ext = self._check_leading_dot(extension)
        if not self.filename.endswith(new_ext):
            # TODO: log that the extension was changed
            self.filename += new_ext

    def create_metadata_file(self, extension) -> Union[Path, bool]:
        # TODO: this method name is confusing
        """
        Create a separate file to hold extracted metadata.

        The string `extension` will be used as the extension for the file.
        """
        ext = self._check_leading_dot(extension)
        try:
            # Prevent using the same path as another file from src_path
            if Path(f'{self.src_path}{ext}').exists():
                raise KittenGroomerError(f'Could not create metadata file for "{self.filename}": a file with that path exists.')
            else:
                self.dst_dir.mkdir(exist_ok=True, parents=True)
                # TODO: shouldn't mutate state and also return something
                self.metadata_file_path = Path(f'{self.dst_path}{ext}')
                return self.metadata_file_path
        # TODO: can probably let this exception bubble up
        except KittenGroomerError as e:
            self.add_error(e, '')
            return False

    def _check_leading_dot(self, ext: str) -> str:
        # TODO: this method name is confusing
        if len(ext) > 0:
            if not ext.startswith('.'):
                return '.' + ext
        return ext

    def _determine_mimetype(self, file_path: str) -> str:
        if os.path.islink(file_path):
            # libmagic will throw an IOError on a broken symlink
            mimetype = 'inode/symlink'
            self.set_property('symlink_path', os.readlink(file_path))
        else:
            try:
                mt = magic.from_file(file_path, mime=True)
                # libmagic always returns something, even if it's just 'data'
            except UnicodeEncodeError as e:
                self.add_error(e, '')
                mt = None
            try:
                mimetype = mt.decode("utf-8")  # type: ignore
            except Exception:
                # FIXME: what should the exception be if mimetype isn't utf-8?
                mimetype = 'application/octet-stream'
        return mimetype

    def _split_mimetype(self, mimetype: str) -> Tuple[Union[str, None], Union[str, None]]:
        main_type, sub_type = None, None
        if mimetype and '/' in mimetype:
            main_type, sub_type = mimetype.split('/')
        return main_type, sub_type

    def _get_size(self, file_path: Path) -> int:
        """Filesize in bytes as an int, 0 if file does not exist."""
        try:
            size = os.path.getsize(file_path)
        except FileNotFoundError:
            size = 0
        return size

    def _remove_exec_bit(self, file_path: Path):
        current_perms = self._get_file_permissions(file_path)
        perms_no_exec = current_perms & (~stat.S_IEXEC)
        os.chmod(file_path, perms_no_exec)

    def _get_file_permissions(self, file_path: Path):
        full_mode = file_path.lstat().st_mode
        return stat.S_IMODE(full_mode)


class Logging(object):

    @staticmethod
    def computehash(path: Path) -> str:
        """Return the sha256 hash of a file at a given path."""
        s = hashlib.sha256()
        with path.open('rb') as f:
            while True:
                buf = f.read(0x100000)
                if not buf:
                    break
                s.update(buf)
        return s.hexdigest()


class KittenGroomerBase(object):
    """Base object responsible for copy/sanitization process."""

    def __init__(self, src_root_path: str, dst_root_path: str):
        """Initialized with path to source and dest directories."""
        self.src_root_path: Path = Path(os.path.abspath(src_root_path))
        self.dst_root_path: Path = Path(os.path.abspath(dst_root_path))

    def safe_rmtree(self, directory_path: Path):
        """Remove a directory tree if it exists."""
        if directory_path.is_dir():
            shutil.rmtree(directory_path)

    def safe_remove(self, file_path: Path):
        """Remove file at file_path if it exists."""
        if file_path.is_file():
            os.remove(file_path)

    def safe_mkdir(self, directory_path: Path):
        """Make a directory if it does not exist."""
        if not directory_path.exists():
            directory_path.mkdir(parents=True)

    def list_all_files(self, directory_path: Path) -> Iterator[Path]:
        """Generator yielding path to all of the files in a directory tree."""
        for root, dirs, files in os.walk(directory_path):
            for filename in files:
                yield Path(root) / filename

    #######################

    def processdir(self, src_dir: Path, dst_dir: Path):
        """Implement this function to define file processing behavior."""
        raise ImplementationRequired('Please implement processdir.')


class KittenGroomerError(Exception):
    """Base KittenGroomer exception handler."""

    def __init__(self, message: str):
        super(KittenGroomerError, self).__init__(message)
        self.message = message


class ImplementationRequired(KittenGroomerError):
    """Implementation required error."""
    pass


def main(
        kg_implementation,
        description=("Call a KittenGroomer implementation to process files "
                     "present in the source directory and copy them to the "
                     "destination directory.")):
    print(description)
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.processdir()
