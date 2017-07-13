#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest.mock as mock

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
    def __init__(self, path, exp_dangerous):
        self.path = path
        self.filename = os.path.basename(path)
        self.exp_dangerous = exp_dangerous


def gather_sample_files():
    file_catalog = read_file_catalog()
    normal_catalog = file_catalog['normal']
    dangerous_catalog = file_catalog['dangerous']
    sample_files = create_sample_files(
        normal_catalog,
        NORMAL_FILES_PATH,
        exp_dangerous=False
    )
    sample_files.extend(create_sample_files(
        dangerous_catalog,
        DANGEROUS_FILES_PATH,
        exp_dangerous=True
    ))
    return sample_files


def read_file_catalog():
    with open(os.path.abspath(CATALOG_PATH)) as catalog_file:
        catalog_dict = yaml.safe_load(catalog_file)
    return catalog_dict


def create_sample_files(file_catalog, dir_path, exp_dangerous):
    sample_files = []
    dir_files = set_of_files(dir_path)
    # Sorted to make the test cases occur in a consistent order, doesn't have to be
    for filename, file_dict in sorted(file_catalog.items()):
        full_path = os.path.abspath(os.path.join(dir_path, filename))
        try:
            dir_files.remove(full_path)
            newfile = SampleFile(full_path, exp_dangerous)
            newfile.xfail = file_dict.get('xfail', False)
            sample_files.append(newfile)
        except KeyError:
            raise FileNotFoundError("{} could not be found".format(filename))
    for file_path in dir_files:
        newfile = SampleFile(file_path, exp_dangerous)
        newfile.xfail = False
        sample_files.append(newfile)
    return sample_files


def set_of_files(dir_path):
    """Set of all full file paths in `dir_path`."""
    full_dir_path = os.path.abspath(dir_path)
    file_paths = set()
    for path in os.listdir(full_dir_path):
        full_path = os.path.join(full_dir_path, path)
        if os.path.isfile(full_path):
            file_paths.add(full_path)
    return file_paths


def get_filename(sample_file):
    return os.path.basename(sample_file.path)


@fixture(scope='module')
def dest_dir_path(tmpdir_factory):
    return tmpdir_factory.mktemp('dest').strpath


@fixture
def groomer(dest_dir_path):
    dummy_src_path = os.getcwd()
    return KittenGroomerFileCheck(dummy_src_path, dest_dir_path, debug=True)


@fixture
def mock_logger(dest_dir_path):
    return mock.MagicMock(spec=GroomerLogger)


@parametrize(
    argnames="sample_file",
    argvalues=gather_sample_files(),
    ids=get_filename)
def test_sample_files(mock_logger, sample_file, groomer, dest_dir_path):
    if sample_file.xfail:
        pytest.xfail(reason='Marked xfail in file catalog')
    file_dest_path = os.path.join(dest_dir_path, sample_file.filename)
    file = File(sample_file.path, file_dest_path, mock_logger)
    groomer.process_file(file)
    assert file.is_dangerous == sample_file.exp_dangerous
