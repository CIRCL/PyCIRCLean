#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import pytest

from kittengroomer import FileBase, KittenGroomerBase, GroomerLogger
from kittengroomer.helpers import ImplementationRequired

skip = pytest.mark.skip
xfail = pytest.mark.xfail
fixture = pytest.fixture


# FileBase

class TestFileBase:

    @fixture
    def source_file(self):
        return 'tests/src_valid/blah.conf'

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
        os.symlink(file_path, symlink_path)
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
        return generic_conf_file

    @fixture
    def file_marked_unknown(self, generic_conf_file):
        generic_conf_file.make_unknown()
        return generic_conf_file

    @fixture
    def file_marked_binary(self, generic_conf_file):
        generic_conf_file.mark_binary()
        return generic_conf_file

    @fixture(params=[
        FileBase.make_dangerous,
        FileBase.make_unknown,
        FileBase.make_binary
    ])
    def file_marked_all_parameterized(self, request, generic_conf_file):
        request.param(generic_conf_file)
        return generic_conf_file

    # What are the various things that can go wrong with file paths? We should have fixtures for them
    # What should FileBase do if it's given a path that isn't a file (doesn't exist or is a dir)? Currently magic throws an exception
    # We should probably catch everytime that happens and tell the user explicitly happened (and maybe put it in the log)

    def test_create(self):
        file = FileBase('tests/src_valid/blah.conf', '/tests/dst/blah.conf')

    def test_create_broken(self, tmpdir):
        with pytest.raises(TypeError):
            file_no_args = FileBase()
        with pytest.raises(FileNotFoundError):
            file_empty_args = FileBase('', '')
        with pytest.raises(IsADirectoryError):
            file_directory = FileBase(tmpdir.strpath, tmpdir.strpath)
        # are there other cases here? path to a file that doesn't exist? permissions?

    def test_init(self, generic_conf_file):
        file = generic_conf_file
        assert file.get_property('filepath') == file.src_path
        assert file.get_property('extension') == '.conf'
        # TODO: should we make log_details undeletable?
        # TODO: we should probably check for more extensions here

    def test_extension_uppercase(self, tmpdir):
        file_path = tmpdir.join('TEST.TXT')
        file_path.write('testing')
        file_path = file_path.strpath
        file = FileBase(file_path, file_path)
        assert file.extension == '.txt'

    def test_mimetypes(self, generic_conf_file):
        assert generic_conf_file.has_mimetype()
        assert generic_conf_file.mimetype == 'text/plain'
        assert generic_conf_file.main_type == 'text'
        assert generic_conf_file.sub_type == 'plain'
        # Need to test something without a mimetype
        # Need to test something that's a directory
        # Need to test something that causes the unicode exception

    def test_has_mimetype_no_main_type(self, generic_conf_file):
        generic_conf_file.main_type = ''
        assert generic_conf_file.has_mimetype() is False

    def test_has_mimetype_no_sub_type(self, generic_conf_file):
        generic_conf_file.sub_type = ''
        assert generic_conf_file.has_mimetype() is False

    def test_has_extension(self, temp_file, temp_file_no_ext):
        assert temp_file.has_extension() is True
        print(temp_file_no_ext.extension)
        assert temp_file_no_ext.has_extension() is False

    def test_set_property(self, generic_conf_file):
        generic_conf_file.set_property('test', True)
        assert generic_conf_file.get_property('test') is True
        assert generic_conf_file.get_property('wrong') is None

    def test_marked_dangerous(self, file_marked_all_parameterized):
        file_marked_all_parameterized.make_dangerous()
        assert file_marked_all_parameterized.is_dangerous() is True
        # Should work regardless of weird paths??
        # Should check file path alteration behavior as well

    def test_generic_dangerous(self, generic_conf_file):
        assert generic_conf_file.is_dangerous() is False
        generic_conf_file.make_dangerous()
        assert generic_conf_file.is_dangerous() is True

    def test_has_symlink(self, tmpdir):
        file_path = tmpdir.join('test.txt')
        file_path.write('testing')
        file_path = file_path.strpath
        symlink_path = tmpdir.join('symlinked.txt')
        symlink_path = symlink_path.strpath
        file_symlink = os.symlink(file_path, symlink_path)
        file = FileBase(file_path, file_path)
        symlink = FileBase(symlink_path, symlink_path)
        assert file.is_symlink() is False
        assert symlink.is_symlink() is True

    def test_has_symlink_fixture(self, symlink):
        assert symlink.is_symlink() is True

    def test_generic_make_unknown(self, generic_conf_file):
        assert generic_conf_file.is_unknown() is False
        generic_conf_file.make_unknown()
        assert generic_conf_file.is_unknown()
        # given a FileBase object with no marking, should do the right things

    def test_marked_make_unknown(self, file_marked_all_parameterized):
        file = file_marked_all_parameterized
        if file.is_unknown():
            file.make_unknown()
            assert file.is_unknown()
        else:
            assert file.is_unknown() is False
            file.make_unknown()
            assert file.is_unknown() is False
        # given a FileBase object with an unrecognized marking, should ???

    def test_generic_make_binary(self, generic_conf_file):
        assert generic_conf_file.is_binary() is False
        generic_conf_file.make_binary()
        assert generic_conf_file.is_binary() is True

    def test_marked_make_binary(self, file_marked_all_parameterized):
        file = file_marked_all_parameterized
        if file.is_dangerous():
            file.make_binary()
            assert file.is_binary() is False
            assert file.get_property('binary') is None
        else:
            file.make_binary()
            assert file.is_binary()
            assert file.get_property('binary') is True

    def test_force_ext_change(self, generic_conf_file):
        assert generic_conf_file.has_extension()
        assert generic_conf_file.get_property('extension') == '.conf'
        assert os.path.splitext(generic_conf_file.dst_path)[1] == '.conf'
        generic_conf_file.force_ext('.txt')
        assert os.path.splitext(generic_conf_file.dst_path)[1] == '.txt'
        assert generic_conf_file.get_property('force_ext') is True
        assert generic_conf_file.get_property('extension') == '.txt'
        # should be able to handle weird paths

    def test_force_ext_correct(self, generic_conf_file):
        assert generic_conf_file.has_extension()
        assert generic_conf_file.get_property('extension') == '.conf'
        generic_conf_file.force_ext('.conf')
        assert os.path.splitext(generic_conf_file.dst_path)[1] == '.conf'
        assert generic_conf_file.get_property('force_ext') is None
        # shouldn't change a file's extension if it already is right

    def test_create_metadata_file(self, temp_file):
        # Try making a metadata file
        metadata_file_path = temp_file.create_metadata_file('.metadata.txt')
        with open(metadata_file_path, 'w+') as metadata_file:
            metadata_file.write('Have some metadata!')
        # Shouldn't be able to make a metadata file with no extension
        assert temp_file.create_metadata_file('') is False
        # if metadata file already exists
        # if there is no metadata to write should this work?


class TestLogger:

    @fixture
    def generic_logger(self, tmpdir):
        return GroomerLogger(tmpdir.strpath)

    def test_tree(self, generic_logger):
        generic_logger.tree(generic_logger.root_dir)


class TestKittenGroomerBase:

    @fixture
    def source_directory(self):
        return 'tests/src_invalid'

    @fixture
    def dest_directory(self):
        return 'tests/dst'

    @fixture
    def generic_groomer(self, source_directory, dest_directory):
        return KittenGroomerBase(source_directory, dest_directory)

    def test_create(self, generic_groomer):
        assert generic_groomer

    def test_instantiation(self, source_directory, dest_directory):
        groomer = KittenGroomerBase(source_directory, dest_directory)
        debug_groomer = KittenGroomerBase(source_directory,
                                          dest_directory,
                                          debug=True)
        # we should maybe protect access to self.current_file in some way?

    def test_safe_copy(self, tmpdir):
        file = tmpdir.join('test.txt')
        file.write('testing')
        testdir = tmpdir.join('testdir')
        os.mkdir(testdir.strpath)
        filedest = testdir.join('test.txt')
        simple_groomer = KittenGroomerBase(tmpdir.strpath, testdir.strpath)
        simple_groomer.cur_file = FileBase(file.strpath, filedest.strpath)
        assert simple_groomer.safe_copy() is True
        #check that it handles weird file path inputs

    def test_list_all_files(self, tmpdir):
        file = tmpdir.join('test.txt')
        file.write('testing')
        testdir = tmpdir.join('testdir')
        os.mkdir(testdir.strpath)
        simple_groomer = KittenGroomerBase(tmpdir.strpath, tmpdir.strpath)
        files = simple_groomer.list_all_files(simple_groomer.src_root_dir)
        assert file.strpath in files
        assert testdir.strpath not in files

    def test_processdir(self, generic_groomer):
        with pytest.raises(ImplementationRequired):
            generic_groomer.processdir(None, None)
