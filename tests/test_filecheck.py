#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil

import pytest

from tests.logging import save_logs
try:
    from bin.filecheck import KittenGroomerFileCheck, File, main
    NODEPS = False
except ImportError:
    NODEPS = True

fixture = pytest.fixture
skip = pytest.mark.skip
skipif_nodeps = pytest.mark.skipif(NODEPS,
                                   reason="Dependencies aren't installed")


@skipif_nodeps
class TestSystem:

    @fixture
    def valid_groomer(self):
        src_path = os.path.join(os.getcwd(), 'tests/normal')
        dst_path = self.make_dst_dir_path(src_path)
        return KittenGroomerFileCheck(src_path, dst_path, debug=True)

    @fixture
    def invalid_groomer(self):
        src_path = os.path.join(os.getcwd(), 'tests/dangerous')
        dst_path = self.make_dst_dir_path(src_path)
        return KittenGroomerFileCheck(src_path, dst_path, debug=True)

    def make_dst_dir_path(self, src_dir_path):
        dst_path = src_dir_path + '_dst'
        shutil.rmtree(dst_path, ignore_errors=True)
        os.makedirs(dst_path, exist_ok=True)
        return dst_path

    def test_filecheck_src_valid(self, valid_groomer):
        valid_groomer.run()
        test_description = "filecheck_valid"
        save_logs(valid_groomer, test_description)

    def test_filecheck_src_invalid(self, invalid_groomer):
        invalid_groomer.run()
        test_description = "filecheck_invalid"
        save_logs(invalid_groomer, test_description)


class TestFileHandling:
    def test_autorun(self):
        # Run on a single autorun file, confirm that it gets flagged as dangerous
        # TODO: build out these and other methods for individual file cases
        pass
