#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest.mock as mock

import pytest

from kittengroomer import FileBase, KittenGroomerBase

skip = pytest.mark.skip
xfail = pytest.mark.xfail
fixture = pytest.fixture


class TestFileBase:

    @fixture(scope='class')
    def dest_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('dest').strpath

    @fixture(scope='class')
    def src_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('src').strpath

    @fixture
    def symlink_file(self, tmpdir):
        file_path = tmpdir.join('test.txt')
        file_path.write('testing')
        file_path = file_path.strpath
        symlink_path = tmpdir.join('symlinked.txt')
        symlink_path = symlink_path.strpath
        os.symlink(file_path, symlink_path)
        return FileBase(symlink_path, symlink_path)

    @fixture
    def temp_file(self, src_dir_path, dst_dir_path):
        file_path = os.path.join(src_dir_path, 'test.txt')
        file_path.write('testing')
        return FileBase(file_path, dst_dir_path)

    @fixture
    def temp_file_no_ext(self, tmpdir):
        file_path = tmpdir.join('test')
        file_path.write('testing')
        file_path = file_path.strpath
        return FileBase(file_path, file_path)

    @fixture
    def file_marked_dangerous(self):
        pass

    @mock.patch('kittengroomer.helpers.magic')
    def test_init_identify_filename(self, mock_magic):
        """Init should identify the filename correctly for src_path."""
        src_path = 'src/test.txt'
        dst_path = 'dst/test.txt'
        file = FileBase(src_path, dst_path)
        assert file.filename == 'test.txt'

    def test_init_uppercase_filename(self):
        """Init should coerce filenames to lowercase."""
        pass

    def test_init_identify_extension(self):
        """Init should identify the extension for src_path."""
        pass

    def test_init_uppercase_extension(self):
        """Init should coerce uppercase extension to lowercase"""
        pass

    def test_init_file_doesnt_exist(self):
        """Init should raise an exception if the file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            FileBase('', '')

    def test_init_srcpath_is_directory(self, tmpdir):
        """Init should raise an exception if given a path to a directory."""
        with pytest.raises(IsADirectoryError):
            FileBase(tmpdir.strpath, tmpdir.strpath)

    def test_init_symlink(self):
        """Init should properly identify symlinks."""
        pass

    def test_is_symlink_attribute(self):
        """If a file is a symlink, is_symlink should return True."""
        pass

    def test_mimetype_attribute_assigned_correctly(self):
        """When libmagic returns a given mimetype, the mimetype should be
        assigned properly."""
        pass

    def set_property_user_defined(self):
        pass

    def set_property_builtin(self):
        pass

    def get_property_doesnt_exist(self):
        pass

    def get_property_builtin(self):
        pass

    def get_property_user_defined(self):
        pass

    def test_has_mimetype_no_main_type(self):
        pass

    def test_has_mimetype_no_sub_type(self):
        pass

    def test_has_extension_true(self):
        pass

    def test_has_extension_false(self):
        pass

    def test_add_new_description(self):
        pass

    def test_add_description_exists(self):
        pass

    def test_add_new_error(self):
        pass

    def test_add_error_exists(self):
        pass

    def test_normal_file_mark_dangerous(self):
        pass

    def test_normal_file_mark_dangerous_filename_change(self):
        pass

    def test_normal_file_mark_dangerous_add_description(self):
        pass

    def test_dangerous_file_mark_dangerous(self):
        pass

    def test_safe_copy(self):
        pass

    def test_force_ext_change(self):
        pass

    def test_force_ext_correct(self):
        pass

    def test_create_metadata_file_new(self):
        pass

    def test_create_metadata_file_already_exists(self):
        pass


class TestKittenGroomerBase:

    @fixture(scope='class')
    def src_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('src').strpath

    @fixture(scope='class')
    def dest_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('dest').strpath

    @fixture
    def generic_groomer(self, src_dir_path, dest_dir_path):
        return KittenGroomerBase(src_dir_path, dest_dir_path)

    def test_list_all_files_includes_file(self, tmpdir):
        file = tmpdir.join('test.txt')
        file.write('testing')
        files = KittenGroomerBase.list_all_files(KittenGroomerBase, tmpdir.strpath)
        assert file.strpath in files

    def test_list_all_files_excludes_dir(self, tmpdir):
        testdir = tmpdir.join('testdir')
        os.mkdir(testdir.strpath)
        files = KittenGroomerBase.list_all_files(KittenGroomerBase, tmpdir.strpath)
        assert testdir.strpath not in files
