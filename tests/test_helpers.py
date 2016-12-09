#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import tempfile

import pytest

from kittengroomer import FileBase
from kittengroomer import KittenGroomerBase

PY3 = sys.version_info.major == 3
skip = pytest.mark.skip
xfail = pytest.mark.xfail
fixture = pytest.fixture


### FileBase

class TestFileBase:

    @fixture
    def source_file(self):
        return 'tests/src_simple/blah.conf'

    @fixture
    def dest_file(self):
        return 'tests/dst/blah.conf'

    @fixture
    def generic_conf_file(self, source_file, dest_file):
        return FileBase(source_file, dest_file)

    @fixture
    def symlink(self, tmpdir):
        file_path = tmpdir.join('test.txt')
        file_path.write('testing')
        file_path = file_path.strpath
        symlink_path = tmpdir.join('symlinked.txt')
        symlink_path = symlink_path.strpath
        file_symlink = os.symlink(file_path, symlink_path)
        return FileBase(symlink_path, symlink_path)

    @fixture
    def temp_file(self, tmpdir):
        file_path = tmpdir.join('test.txt')
        file_path.write('testing')
        file_path = file_path.strpath
        return FileBase(file_path, file_path)

    @fixture
    def temp_file_no_ext(self, tmpdir):
        file_path = tmpdir.join('test')
        file_path.write('testing')
        file_path = file_path.strpath
        return FileBase(file_path, file_path)

    @fixture
    def file_marked_dangerous(self, generic_conf_file):
        generic_conf_file.make_dangerous()
        return file

    @fixture
    def file_marked_unknown(self, generic_conf_file):
        generic_conf_file.make_unknown()
        return file

    @fixture
    def file_marked_binary(self, generic_conf_file):
        generic_conf_file.mark_binary()
        return file

    @fixture(params=[
        FileBase.make_dangerous,
        FileBase.make_unknown,
        FileBase.make_binary
    ])
    def file_marked_all_parameterized(self, request, generic_conf_file):
        request.param(generic_conf_file)
        return generic_conf_file

    # What are the various things that can go wrong with file paths? We should have fixtures for them
    # What should the object do if it's given a path that isn't a file? Currently magic throws an exception
    # We should probably catch everytime that happens and tell the user what happened (and maybe put it in the log)

    def test_create(self):
        file = FileBase('tests/src_simple/blah.conf', '/tests/dst/blah.conf')

    def test_create_broken(self, tmpdir):
        with pytest.raises(TypeError):
            file_no_args = FileBase()
        if PY3:
            with pytest.raises(FileNotFoundError):
                file_empty_args = FileBase('', '')
        else:
            with pytest.raises(IOError):
                file_empty_args = FileBase('', '')
        if PY3:
            with pytest.raises(IsADirectoryError):
                file_directory = FileBase(tmpdir.strpath, tmpdir.strpath)
        else:
            with pytest.raises(IOError):
                file_directory = FileBase(tmpdir.strpath, tmpdir.strpath)
        # are there other cases here? path to a file that doesn't exist? permissions?

    def test_init(self, generic_conf_file):
        file = generic_conf_file
        assert file.log_details
        assert file.log_details['filepath'] == file.src_path
        assert file.extension == '.conf'
        copied_log = file.log_details.copy()
        file.log_details = ''
        # assert file.log_details == copied_log     # this fails for now, we need to make log_details undeletable
        # we should probably check for more extensions here

    def test_mimetypes(self, generic_conf_file):
        assert generic_conf_file.has_mimetype()
        assert generic_conf_file.mimetype == 'text/plain'
        assert generic_conf_file.main_type == 'text'
        assert generic_conf_file.sub_type == 'plain'
        # FileBase(source_path)
        # this is essentially testing the behavior of magic. I guess for now it's ok if we just test for some basic file types?

    def test_has_extension(self, temp_file, temp_file_no_ext):
        assert temp_file.has_extension() == True
        assert temp_file_no_ext.has_extension() == False
        assert temp_file_no_ext.log_details.get('no_extension') == True

    def test_marked_dangerous(self, file_marked_all_parameterized):
        file_marked_all_parameterized.make_dangerous()
        assert file_marked_all_parameterized.is_dangerous() == True
        # Should work regardless of weird paths??
        # Should check file path alteration behavior as well

    def test_generic_dangerous(self, generic_conf_file):
        assert generic_conf_file.is_dangerous() == False
        generic_conf_file.make_dangerous()
        assert generic_conf_file.is_dangerous() == True

    def test_has_symlink(self, tmpdir):
        file_path = tmpdir.join('test.txt')
        file_path.write('testing')
        file_path = file_path.strpath
        symlink_path = tmpdir.join('symlinked.txt')
        symlink_path = symlink_path.strpath
        file_symlink = os.symlink(file_path, symlink_path)
        file = FileBase(file_path, file_path)
        symlink = FileBase(symlink_path, symlink_path)
        assert file.is_symlink() == False
        assert symlink.is_symlink() == True

    def test_has_symlink_fixture(self, symlink):
        assert symlink.is_symlink() == True

    def test_generic_make_unknown(self, generic_conf_file):
        assert generic_conf_file.log_details.get('unknown') == None
        generic_conf_file.make_unknown()
        assert generic_conf_file.log_details.get('unknown') == True
        # given a FileBase object with no marking, should do the right things

    def test_marked_make_unknown(self, file_marked_all_parameterized):
        file = file_marked_all_parameterized
        if file.log_details.get('unknown'):
            file.make_unknown()
            assert file.log_details.get('unknown') == True
        else:
            assert file.log_details.get('unknown') == None
            file.make_unknown()
            assert file.log_details.get('unknown') == None
        # given a FileBase object with an unrecognized marking, should ???

    def test_generic_make_binary(self, generic_conf_file):
        assert generic_conf_file.log_details.get('binary') == None
        generic_conf_file.make_binary()
        assert generic_conf_file.log_details.get('binary') == True

    def test_marked_make_binary(self, file_marked_all_parameterized):
        file = file_marked_all_parameterized
        if file.log_details.get('dangerous'):
            file.make_binary()
            assert file.log_details.get('binary') == None
        else:
            file.make_binary()
            assert file.log_details.get('binary') == True

    def test_force_ext_change(self, generic_conf_file):
        assert generic_conf_file.has_extension()
        assert generic_conf_file.extension == '.conf'
        assert os.path.splitext(generic_conf_file.dst_path)[1] == '.conf'
        generic_conf_file.force_ext('.txt')
        assert os.path.splitext(generic_conf_file.dst_path)[1] == '.txt'
        assert generic_conf_file.log_details.get('force_ext') == True
        # should make a file's extension change
        # should be able to handle weird paths

    def test_force_ext_correct(self, generic_conf_file):
        assert generic_conf_file.has_extension()
        assert generic_conf_file.extension == '.conf'
        generic_conf_file.force_ext('.conf')
        assert os.path.splitext(generic_conf_file.dst_path)[1] == '.conf'
        assert generic_conf_file.log_details.get('force_ext') == None
        # shouldn't change a file's extension if it already is right


class TestKittenGroomerBase:
    
    @fixture
    def generic_groomer(self):
        return KittenGroomerBase('tests/src_complex', 'tests/dst')

    def test_create(self, generic_groomer):
        assert generic_groomer

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
