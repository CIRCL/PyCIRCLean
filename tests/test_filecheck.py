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

skipif_nodeps = pytest.mark.skipif(NODEPS,
                                   reason="Dependencies aren't installed")


@skipif_nodeps
class TestIntegration:

    @pytest.fixture
    def src_valid_path(self):
        return os.path.join(os.getcwd(), 'tests/src_valid')

    @pytest.fixture
    def src_invalid_path(self):
        return os.path.join(os.getcwd(), 'tests/src_invalid')

    @pytest.fixture
    def dst(self):
        return os.path.join(os.getcwd(), 'tests/dst')

    def test_filecheck_src_invalid(self, src_invalid_path):
        dst_path = self.make_dst_dir_path(src_invalid_path)
        groomer = KittenGroomerFileCheck(src_invalid_path, dst_path, debug=True)
        groomer.run()
        test_description = "filecheck_invalid"
        save_logs(groomer, test_description)

    def test_filecheck_2(self, src_valid_path):
        dst_path = self.make_dst_dir_path(src_valid_path)
        groomer = KittenGroomerFileCheck(src_valid_path, dst_path, debug=True)
        groomer.run()
        test_description = "filecheck_valid"
        save_logs(groomer, test_description)

    def test_processdir(self):
        pass

    def test_handle_archives(self):
        pass

    def make_dst_dir_path(self, src_dir_path):
        dst_path = src_dir_path + '_dst'
        shutil.rmtree(dst_path, ignore_errors=True)
        os.makedirs(dst_path, exist_ok=True)
        return dst_path


class TestFileHandling:
    def test_autorun(self):
        # Run on a single autorun file, confirm that it gets flagged as dangerous
        # TODO: build out these and other methods for individual file cases
        pass
