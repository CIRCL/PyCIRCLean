#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil

import pytest

from tests.utils import save_logs, SampleFile
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
    full_dir_path = os.path.abspath(dir_path)
    files = []
    for file_path in os.listdir(full_dir_path):
        full_file_path = os.path.join(full_dir_path, file_path)
        _, ext = os.path.splitext(full_file_path)
        if os.path.isfile(full_file_path) and ext is not '.expect':
            files.append(full_file_path)
    return files


def construct_sample_files(file_paths, expect_dangerous):
    complex_exts = {'.gif', '.jpg', '.png', '.svg', '.rar', '.zip'}
    files = []
    for path in file_paths:
        newfile = SampleFile(path, expect_dangerous)
        _, extension = os.path.splitext(path)
        if extension in complex_exts:
            newfile.groomer_needed = True
        else:
            newfile.groomer_needed = False
        files.append(newfile)
    return files


def filename(argvalue):
    return os.path.basname(argvalue)


@parametrize(argnames="sample_file", argvalues=gather_sample_files())
def test_sample_files(sample_file):
    if not sample_file.groomer_needed:
        file = File(sample_file.path, '', GroomerLogger)
        file.check()
        assert file.is_dangerous is sample_file.expect_dangerous


@fixture
def valid_groomer():
    src_path = os.path.join(os.getcwd(), 'tests/normal')
    dst_path = make_dst_dir_path(src_path)
    return KittenGroomerFileCheck(src_path, dst_path, debug=True)


@fixture
def invalid_groomer():
    src_path = os.path.join(os.getcwd(), 'tests/dangerous')
    dst_path = make_dst_dir_path(src_path)
    return KittenGroomerFileCheck(src_path, dst_path, debug=True)


def make_dst_dir_path(src_dir_path):
    dst_path = src_dir_path + '_dst'
    shutil.rmtree(dst_path, ignore_errors=True)
    os.makedirs(dst_path, exist_ok=True)
    return dst_path


@skip
def test_filecheck_src_valid(valid_groomer):
    valid_groomer.run()
    test_description = "filecheck_valid"
    save_logs(valid_groomer, test_description)


@skip
def test_filecheck_src_invalid(invalid_groomer):
    invalid_groomer.run()
    test_description = "filecheck_invalid"
    save_logs(invalid_groomer, test_description)
