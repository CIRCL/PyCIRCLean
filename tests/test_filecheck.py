#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

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
    def src_valid(self):
        return os.path.join(os.getcwd(), 'tests/src_valid')

    @pytest.fixture
    def src_invalid(self):
        return os.path.join(os.getcwd(), 'tests/src_invalid')

    @pytest.fixture
    def dst(self):
        return os.path.join(os.getcwd(), 'tests/dst')

    def test_filecheck(self, src_invalid, dst):
        groomer = KittenGroomerFileCheck(src_invalid, dst, debug=True)
        groomer.processdir()
        test_description = "filecheck_invalid"
        save_logs(groomer, test_description)

    def test_filecheck_2(self, src_valid, dst):
        groomer = KittenGroomerFileCheck(src_valid, dst, debug=True)
        groomer.processdir()
        test_description = "filecheck_valid"
        save_logs(groomer, test_description)


class TestFileHandling:
    pass
