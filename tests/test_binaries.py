#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

import pytest

from bin.specific import KittenGroomerSpec
from bin.pier9 import KittenGroomerPier9
from bin.generic import KittenGroomer
from bin.filecheck import KittenGroomerFileCheck


skip = pytest.mark.skip
py2_only = pytest.mark.skipif(sys.version_info.major == 3,
                                reason="filecheck.py only runs on python 2")


@pytest.fixture
def src_simple():
    return os.path.join(os.getcwd(), 'tests/src_simple')


@pytest.fixture
def src_complex():
    return os.path.join(os.getcwd(), 'tests/src_complex')


@pytest.fixture
def dst():
    return os.path.join(os.getcwd(), 'tests/dst')


def test_specific_valid(src_simple, dst):
    spec = KittenGroomerSpec(src_simple, dst, debug=True)
    spec.processdir()
    dump_logs(spec)


def test_specific_invalid(src_complex, dst):
    spec = KittenGroomerSpec(src_complex, dst, debug=True)
    spec.processdir()
    dump_logs(spec)


def test_pier9(src_complex, dst):
    spec = KittenGroomerPier9(src_complex, dst, debug=True)
    spec.processdir()
    dump_logs(spec)


def test_generic(src_simple, dst):
    spec = KittenGroomer(src_simple, dst, debug=True)
    spec.processdir()
    dump_logs(spec)


def test_generic_2(src_complex, dst):
    spec = KittenGroomer(src_complex, dst, debug=True)
    spec.processdir()
    dump_logs(spec)


def test_filecheck(src_complex, dst):
    spec = KittenGroomerFileCheck(src_complex, dst, debug=True)
    spec.processdir()
    dump_logs(spec)


def test_filecheck_2(src_simple, dst):
    spec = KittenGroomerFileCheck(src_simple, dst, debug=True)
    spec.processdir()
    dump_logs(spec)

## Helper functions

def dump_logs(spec):
    print(open(spec.log_processing, 'rb').read())
    if spec.debug:
        if os.path.exists(spec.log_debug_err):
            print(open(spec.log_debug_err, 'rb').read())
        if os.path.exists(spec.log_debug_out):
            print(open(spec.log_debug_out, 'rb').read())
