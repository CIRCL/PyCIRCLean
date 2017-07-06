#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import pytest
import yaml

try:
    from bin.filecheck import KittenGroomerFileCheck, File, GroomerLogger
    NODEPS = False
except ImportError:
    NODEPS = True
pytestmark = pytest.mark.skipif(NODEPS, reason="Dependencies aren't installed")


fixture = pytest.fixture
skip = pytest.mark.skip
parametrize = pytest.mark.parametrize


NORMAL_FILES_PATH = 'tests/normal/'
DANGEROUS_FILES_PATH = 'tests/dangerous/'
CATALOG_PATH = 'tests/file_catalog.yaml'


class SampleFile():
    def __init__(self, path, expect_dangerous):
        self.path = path
        self.expect_dangerous = expect_dangerous
        self.filename = os.path.basename(self.path)

    @property
    def expect_path(self):
        return self.path + '.expect'

    @property
    def has_expect_file(self):
        return os.path.isfile(self.expect_path)

    def parse_expect(self):
        with open(self.expect_path, 'r') as expect_file:
            self.expect_dict = yaml.safe_load(expect_file)
        self.expect_dangerous = self.expect_dict['expect_dangerous']
        self.groomer_needed = self.expect_dict['groomer_needed']
        self.expected_mimetype = self.expect_dict['expected_mimetype']


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
    files = []
    for path in file_paths:
        newfile = SampleFile(path, expect_dangerous)
        if newfile.has_expect_file:
            newfile.parse_expect()
        files.append(newfile)
    return files


def get_filename(sample_file):
    return os.path.basename(sample_file.path)


@fixture(scope='session')
def dest_dir_path(tmpdir_factory):
    return tmpdir_factory.mktemp('dest').strpath


@fixture
def groomer(dest_dir_path):
    dummy_src_path = os.getcwd()
    return KittenGroomerFileCheck(dummy_src_path, dest_dir_path, debug=True)


@fixture
def logger(dest_dir_path):
    return GroomerLogger()


@parametrize(
    argnames="sample_file",
    argvalues=gather_sample_files(),
    ids=get_filename)
def test_sample_files(sample_file, groomer, dest_dir_path):
    file_dest_path = dest_dir_path + sample_file.filename
    file = File(sample_file.path, file_dest_path, groomer.logger)
    groomer.process_file(file)
    assert file.is_dangerous is sample_file.expect_dangerous
    if sample_file.has_expect_file:
        assert file.mimetype == sample_file.expected_mimetype
