#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest.mock as mock

import pytest

from kittengroomer import FileBase, KittenGroomerBase
from kittengroomer.helpers import ImplementationRequired

skip = pytest.mark.skip
xfail = pytest.mark.xfail
fixture = pytest.fixture


class TestFileBase:

    @fixture(scope='class')
    def src_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('src').strpath

    @fixture(scope='class')
    def dest_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('dest').strpath

    @fixture
    def tmpfile_path(self, tmpdir):
        file_path = tmpdir.join('test.txt')
        file_path.write('testing')
        return file_path.strpath

    @fixture
    def symlink_file_path(self, tmpdir, tmpfile_path):
        symlink_path = tmpdir.join('symlinked')
        symlink_path = symlink_path.strpath
        os.symlink(tmpfile_path, symlink_path)
        return symlink_path

    @fixture
    def text_file(self):
        with mock.patch(
            'kittengroomer.helpers.magic.from_file',
            return_value='text/plain'
        ):
            src_path = 'src/test.txt'
            dst_path = 'dst/test.txt'
            file = FileBase(src_path, dst_path)
        return file

    # Constructor behavior

    @mock.patch('kittengroomer.helpers.magic')
    def test_init_identify_filename(self, mock_libmagic):
        """Init should identify the filename correctly for src_path."""
        src_path = 'src/test.txt'
        dst_path = 'dst/test.txt'
        file = FileBase(src_path, dst_path)
        assert file.filename == 'test.txt'

    @mock.patch('kittengroomer.helpers.magic')
    def test_init_identify_extension(self, mock_libmagic):
        """Init should identify the extension for src_path."""
        src_path = 'src/test.txt'
        dst_path = 'dst/test.txt'
        file = FileBase(src_path, dst_path)
        assert file.extension == '.txt'

    @mock.patch('kittengroomer.helpers.magic')
    def test_init_uppercase_extension(self, mock_libmagic):
        """Init should coerce uppercase extension to lowercase"""
        src_path = 'src/TEST.TXT'
        dst_path = 'dst/TEST.TXT'
        file = FileBase(src_path, dst_path)
        assert file.extension == '.txt'

    @mock.patch('kittengroomer.helpers.magic')
    def test_has_extension_true(self, mock_libmagic):
        """If the file has an extension, has_extension should == True."""
        src_path = 'src/test.txt'
        dst_path = 'dst/test.txt'
        file = FileBase(src_path, dst_path)
        assert file.has_extension is True

    @mock.patch('kittengroomer.helpers.magic')
    def test_has_extension_false(self, mock_libmagic):
        """If the file has no extension, has_extensions should == False."""
        src_path = 'src/test'
        dst_path = 'dst/test'
        file = FileBase(src_path, dst_path)
        assert file.has_extension is False

    def test_init_file_doesnt_exist(self):
        """Init should raise an exception if the file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            FileBase('', '')

    def test_init_srcpath_is_directory(self, tmpdir):
        """Init should raise an exception if given a path to a directory."""
        with pytest.raises(IsADirectoryError):
            FileBase(tmpdir.strpath, tmpdir.strpath)

    @mock.patch('kittengroomer.helpers.magic')
    def test_init_symlink(self, mock_libmagic, symlink_file_path):
        """Init should properly identify symlinks."""
        file = FileBase(symlink_file_path, '')
        assert file.mimetype == 'inode/symlink'

    @mock.patch('kittengroomer.helpers.magic')
    def test_is_symlink_attribute(self, mock_libmagic, symlink_file_path):
        """If a file is a symlink, is_symlink should return True."""
        file = FileBase(symlink_file_path, '')
        assert file.is_symlink is True

    def test_init_mimetype_attribute_assigned_correctly(self):
        """When libmagic returns a given mimetype, the mimetype should be
        assigned properly."""
        with mock.patch('kittengroomer.helpers.magic.from_file',
                        return_value='text/plain'):
            file = FileBase('', '')
        assert file.mimetype == 'text/plain'

    def test_maintype_and_subtype_attributes(self):
        """If a file has a full mimetype, maintype and subtype should ==
        the appropriate values."""
        with mock.patch('kittengroomer.helpers.magic.from_file',
                        return_value='text/plain'):
            file = FileBase('', '')
        assert file.maintype == 'text'
        assert file.subtype == 'plain'

    def test_has_mimetype_no_full_type(self):
        """If a file doesn't have a full mimetype has_mimetype should == False."""
        with mock.patch('kittengroomer.helpers.magic.from_file',
                        return_value='data'):
            file = FileBase('', '')
        assert file.has_mimetype is False

    def test_has_mimetype_mimetype_is_none(self):
        """If a file doesn't have a full mimetype has_mimetype should == False."""
        with mock.patch('kittengroomer.helpers.FileBase._determine_mimetype',
                        return_value=None):
            file = FileBase('', '')
        assert file.has_mimetype is False

    # File properties

    def get_property_doesnt_exist(self, text_file):
        """Trying to get a property that doesn't exist should return None."""
        assert text_file.get_property('thing') is None

    def get_property_builtin(self, text_file):
        """Getting a property that's been set should return that property."""
        assert text_file.get_property('is_dangerous') is False

    def get_property_user_defined(self, text_file):
        """Getting a user defined property should return that property."""
        text_file._user_defined = {'thing': True}
        assert text_file.get_property('thing') is True

    def set_property_user_defined(self, text_file):
        """Setting a non-default property should make it available for
        get_property."""
        text_file.set_property('thing', True)
        assert text_file.get_property('thing') is True

    def set_property_builtin(self, text_file):
        """Setting a builtin property should assign that property."""
        text_file.set_property('is_dangerous', True)
        assert text_file.get_property('is_dangerous') is True

    def test_add_new_description(self, text_file):
        """Adding a new description should add it to the list of description strings."""
        text_file.add_description('thing')
        assert text_file.get_property('description_string') == 'thing'

    def test_add_description_exists(self, text_file):
        """Adding a description that already exists shouldn't duplicate it."""
        text_file.add_description('thing')
        text_file.add_description('thing')
        assert text_file.get_property('description_string') == 'thing'

    def test_add_multiple_descriptions(self, text_file):
        text_file.add_description('thing')
        text_file.add_description('foo')
        assert text_file.get_property('description_string') == 'thing, foo'

    def test_add_description_not_string(self, text_file):
        """Adding a description that isn't a string should raise an error."""
        with pytest.raises(TypeError):
            text_file.add_description(123)

    def test_add_new_error(self, text_file):
        """Adding a new error should add it to the dict of errors."""
        text_file.add_error(Exception, 'thing')
        assert text_file.get_property('_errors') == {Exception: 'thing'}

    def test_normal_file_mark_dangerous(self, text_file):
        """Marking a file dangerous should identify it as dangerous."""
        text_file.make_dangerous()
        assert text_file.is_dangerous is True

    def test_normal_file_mark_dangerous_filename_change(self, text_file):
        """Marking a file dangerous should mangle the filename."""
        filename = text_file.filename
        text_file.make_dangerous()
        assert text_file.filename == 'DANGEROUS_{}_DANGEROUS'.format(filename)

    def test_normal_file_mark_dangerous_add_description(self, text_file):
        """Marking a file as dangerous and passing in a description should add
        that description to the file."""
        text_file.make_dangerous('thing')
        assert text_file.get_property('description_string') == 'thing'

    def test_dangerous_file_mark_dangerous(self, text_file):
        """Marking a dangerous file as dangerous should do nothing, and the
        file should remain dangerous."""
        text_file.make_dangerous()
        text_file.make_dangerous()
        assert text_file.is_dangerous is True

    def test_force_ext_change_filepath(self, text_file):
        """Force_ext should modify the path of the file to end in the
        new extension."""
        text_file.force_ext('.test')
        assert text_file.dst_path.endswith('.test')

    def test_force_ext_add_dot(self, text_file):
        """Force_ext should add a dot to an extension given without one."""
        text_file.force_ext('test')
        assert text_file.dst_path.endswith('.test')

    def test_force_ext_change_extension_attr(self, text_file):
        """Force_ext should modify the extension attribute"""
        text_file.force_ext('.thing')
        assert text_file.extension == '.thing'

    def test_force_ext_no_change(self, text_file):
        """Force_ext should do nothing if the current extension is the same
        as the new extension."""
        text_file.force_ext('.txt')
        assert text_file.extension == '.txt'
        assert '.txt.txt' not in text_file.dst_path

    def test_safe_copy_calls_copy(self, src_dir_path, dest_dir_path):
        """Calling safe_copy should copy the file from the correct path to
        the correct destination path."""
        file_path = os.path.join(src_dir_path, 'test.txt')
        with open(file_path, 'w+') as file:
            file.write('')
        dst_path = os.path.join(dest_dir_path, 'test.txt')
        with mock.patch('kittengroomer.helpers.magic.from_file',
                        return_value='text/plain'):
            file = FileBase(file_path, dst_path)
        with mock.patch('kittengroomer.helpers.shutil.copy') as mock_copy:
            file.safe_copy()
            mock_copy.assert_called_once_with(file_path, dst_path)

    def test_safe_copy_removes_exec_perms(self):
        """`safe_copy` should create a file that doesn't have any of the
        executable bits set."""
        pass

    def test_safe_copy_makedir_doesnt_exist(self):
        """Calling safe_copy should create intermediate directories in the path
        if they don't exist."""
        pass

    def test_safe_copy_makedir_exists(self):
        """Calling safe_copy when some intermediate directories exist should
        result in the creation of the full path and the file."""
        pass

    def test_create_metadata_file_new(self):
        pass

    def test_create_metadata_file_already_exists(self):
        pass


class TestLogging:

    def test_computehash(self):
        """Computehash should return the correct sha256 hash of a given file."""
        pass


class TestKittenGroomerBase:

    @fixture(scope='class')
    def src_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('src').strpath

    @fixture(scope='class')
    def dest_dir_path(self, tmpdir_factory):
        return tmpdir_factory.mktemp('dest').strpath

    @fixture
    def groomer(self, src_dir_path, dest_dir_path):
        return KittenGroomerBase(src_dir_path, dest_dir_path)

    def test_list_all_files_includes_file(self, tmpdir, groomer):
        """Calling list_all_files should include files in the given path."""
        file = tmpdir.join('test.txt')
        file.write('testing')
        files = groomer.list_all_files(tmpdir.strpath)
        assert file.strpath in files

    def test_list_all_files_excludes_dir(self, tmpdir, groomer):
        """Calling list_all_files shouldn't include directories in the given
        path."""
        testdir = tmpdir.join('testdir')
        os.mkdir(testdir.strpath)
        files = groomer.list_all_files(tmpdir.strpath)
        assert testdir.strpath not in files

    def test_safe_remove(self, groomer, src_dir_path):
        """Calling safe_remove should not raise an Exception if trying to
        remove a file that doesn't exist."""
        groomer.safe_remove(os.path.join(src_dir_path, 'thing'))

    def test_safe_mkdir_file_exists(self, groomer, dest_dir_path):
        """Calling safe_mkdir should not overwrite an existing directory."""
        filepath = os.path.join(dest_dir_path, 'thing')
        os.mkdir(filepath)
        groomer.safe_mkdir(filepath)

    def test_processdir_not_implemented(self, groomer):
        """Calling processdir should raise an Implementation Required error."""
        with pytest.raises(ImplementationRequired):
            groomer.processdir('.', '.')
