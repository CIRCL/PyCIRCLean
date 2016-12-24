#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import pytest

from bin.generic import KittenGroomer, File, main
from tests.logging import save_logs

skipif_nodeps = pytest.mark.skipif(os.path.exists('/usr/bin/unoconv') is False,
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

    def test_generic(self, src_valid, dst):
        groomer = KittenGroomer(src_valid, dst, debug=True)
        groomer.processdir()
        test_description = 'generic_valid'
        save_logs(groomer, test_description)

    def test_generic_2(self, src_invalid, dst):
        groomer = KittenGroomer(src_invalid, dst, debug=True)
        groomer.processdir()
        test_description = 'generic_invalid'
        save_logs(groomer, test_description)


class TestFileHandling:
    pass

    # We're going to give KittenGroomer a bunch of files, and it's going to process them
    # Maybe we want to make a function that processdir delegates to? Or is it just the File Object that's responsible?
    # Ideally we should be able to pass a path to a function and have it do stuff? And then we can test that function?
    # So we have a function that takes a path and returns...log info? That makes sense actually. Or some sort of meta data
    # The function could maybe be called processfile
