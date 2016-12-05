#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import Mock

from kittengroomer import FileBase
from kittengroomer import KittenGroomerBase

### FileBase

class TestFileBase:

    @pytest.fixture
    def empty_filebase(self):
        return FileBase('tests/src_simple/blah.conf', '/tests/dst')

    # How do we mock various things that can go wrong with file paths?
    # What should the object do if it's given a path that isn't a file?
    # We should probably catch everytime that happens and tell the user.

    def test_mimetypes(self):
        # the various possible mimetypes including broken ones need to be checked for the right behavior
        pass


    def test_init(self, empty_filebase):
        # src_path or dest_path could be invalid
        # log could be not created
        # what happens if we try to make a new log?
        # split extension should handle various weird paths as well
        pass


    def test_dangerous(self):
        # given a FileBase object marked as dangerous, should do nothing
        # given a FileBase object marked as all other things, should mark as dangerous
        # Should work regardless of weird paths??
        pass


    def test_has_symlink(self):
        # given a FileBase object initialized on a symlink, should identify it as a symlink
        # given a FileBase object initialized as not a symlink, shouldn't do anything
        pass


    def test_make_unknown(self):
        # given a FileBase object with no marking, should do the right things
        # given a FileBase object marked unknown, should do nothing
        # given a FileBase object marked dangerous, should do nothing
        # given a FileBase object with an unrecognized marking, should ???
        pass


    def test_make_binary(self):
        # same as above but for binary
        pass


    def test_force_ext(self):
        # should make a file's extension change
        # shouldn't change a file's extension if it already is right
        # should be able to handle weird paths and filetypes
        pass


class TestKittenGroomerBase:
    
    def test_instantiation(self):
        # src_path and dest_path
        # what if the log file already exists?
        # we should probably protect access to self.current_file in some way?
        pass


    def test_computehash(self):
        # what are the ways this could go wrong? Should give the same hash every time?
        # what is buf doing here?
        pass


    def test_safe_copy(self):
        #check that it handles weird file path inputs
        pass


    def test_safe_metadata_split(self):
        # if metadata file already exists
        # if there is no metadata to write should this work?
        # check that returned file is writable?
        pass


    def test_list_all_files(self):
        # various possible types of directories
        # invalid directory
        pass
