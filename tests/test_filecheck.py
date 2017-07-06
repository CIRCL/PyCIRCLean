#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import pytest

from tests.utils import SampleFile
try:
    from bin.filecheck import KittenGroomerFileCheck, File, GroomerLogger
    NODEPS = False
except ImportError:
    NODEPS = True


fixture = pytest.fixture
skip = pytest.mark.skip
parametrize = pytest.mark.parametrize
pytestmark = pytest.mark.skipif(NODEPS, reason="Dependencies aren't installed")


NORMAL_FILES_PATH = 'tests/normal/'
DANGEROUS_FILES_PATH = 'tests/dangerous/'


def gather_sample_files():
    normal_paths = list_files(NORMAL_FILES_PATH)
    dangerous_paths = list_files(DANGEROUS_FILES_PATH)
    normal_files = construct_sample_files(normal_paths, expect_dangerous=False)
    dangerous_files = construct_sample_files(dangerous_paths, expect_dangerous=True)
    return normal_files + dangerous_files


def list_files(dir_path):
    """List all files in `dir_path`, ignoring .expect files."""
    full_dir_path = os.path.abspath(dir_path)
    files = []
    for file_path in os.listdir(full_dir_path):
        full_file_path = os.path.join(full_dir_path, file_path)
        _, ext = os.path.splitext(full_file_path)
        if os.path.isfile(full_file_path) and not ext.endswith('.expect'):
            files.append(full_file_path)
    return files


def construct_sample_files(file_paths, expect_dangerous):
    """Construct a list of a sample files from list `file_paths`."""
    complex_exts = {'.gif', '.jpg', '.png', '.svg', '.rar', '.zip'}
    files = []
    for path in file_paths:
        newfile = SampleFile(path, expect_dangerous)
        if newfile.has_expect_file:
            newfile.parse_expect()
        _, extension = os.path.splitext(path)
        if extension in complex_exts:
            newfile.groomer_needed = True
        else:
            newfile.groomer_needed = False
        files.append(newfile)
    return files


def get_filename(sample_file):
    return os.path.basename(sample_file.path)


@parametrize(
    argnames="sample_file",
    argvalues=gather_sample_files(),
    ids=get_filename)
def test_sample_files(sample_file, groomer, tmpdir):
    # make groomer (from ? to tmpdir)
    # make file (from file.strpath to tmpdir)
    # run groomer.process_file on it
    # do asserts
    if not sample_file.groomer_needed:
        file = File(sample_file.path, tmpdir.strpath, GroomerLogger)
        file.check()
        assert file.is_dangerous is sample_file.expect_dangerous
    if sample_file.groomer_needed:
        pass
        # TODO: make a groomer and process the sample file here
    if sample_file.has_expect_file:
        assert file.mimetype == sample_file.expected_mimetype


@pytest.fixture
def dest_dir(tmpdir_factory):
    return tmpdir_factory.mktemp('dest')


@fixture
def groomer(tmpdir):
    dummy_src_path = os.getcwd()
    dest_dir = tmpdir.strpath
    return KittenGroomerFileCheck(dummy_src_path, dest_dir, debug=True)
