#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import pytest

from bin.specific import KittenGroomerSpec
from bin.pier9 import KittenGroomerPier9
from tests.logging import save_logs


@pytest.fixture
def src_valid():
    return os.path.join(os.getcwd(), 'tests/src_valid')


@pytest.fixture
def src_invalid():
    return os.path.join(os.getcwd(), 'tests/src_invalid')


@pytest.fixture
def dst():
    return os.path.join(os.getcwd(), 'tests/dst')


def test_specific_valid(src_valid, dst):
    groomer = KittenGroomerSpec(src_valid, dst, debug=True)
    groomer.processdir()
    test_description = 'specific_valid'
    save_logs(groomer, test_description)


def test_specific_invalid(src_invalid, dst):
    groomer = KittenGroomerSpec(src_invalid, dst, debug=True)
    groomer.processdir()
    test_description = 'specific_invalid'
    save_logs(groomer, test_description)


def test_pier9_valid(src_invalid, dst):
    groomer = KittenGroomerPier9(src_invalid, dst, debug=True)
    groomer.processdir()
    test_description = 'pier9_valid'
    save_logs(groomer, test_description)


def test_pier9_invalid(src_invalid, dst):
    groomer = KittenGroomerPier9(src_invalid, dst, debug=True)
    groomer.processdir()
    test_description = 'pier9_invalid'
    save_logs(groomer, test_description)
