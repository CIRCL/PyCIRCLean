#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

import pytest

from bin.specific import KittenGroomerSpec
from bin.pier9 import KittenGroomerPier9
from bin.generic import KittenGroomer

if sys.version_info.major == 2:
    from bin.filecheck import KittenGroomerFileCheck


def setup_module():
    PY3 = sys.version_info.major == 3
    CURPATH = os.getcwd()


def test_specific_valid(self):
    src = os.path.join(CURPATH, 'tests/src2')
    dst = os.path.join(CURPATH, 'tests/dst')
    spec = KittenGroomerSpec(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

def test_specific_invalid(self):
    src = os.path.join(CURPATH, 'tests/src')
    dst = os.path.join(CURPATH, 'tests/dst')
    spec = KittenGroomerSpec(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

def test_pier9(self):
    src = os.path.join(CURPATH, 'tests/src')
    dst = os.path.join(CURPATH, 'tests/dst')
    spec = KittenGroomerPier9(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

def test_generic(self):
    src = os.path.join(CURPATH, 'tests/src2')
    dst = os.path.join(CURPATH, 'tests/dst')
    spec = KittenGroomer(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

def test_generic_2(self):
    src = os.path.join(CURPATH, 'tests/src')
    dst = os.path.join(CURPATH, 'tests/dst')
    spec = KittenGroomer(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

def test_filecheck(self):
    if PY3:
        return
    src = os.path.join(CURPATH, 'tests/src')
    dst = os.path.join(CURPATH, 'tests/dst')
    spec = KittenGroomerFileCheck(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

def test_filecheck_2(self):
    if PY3:
        return
    src = os.path.join(self.CURPATH, 'tests/src2')
    dst = os.path.join(self.CURPATH, 'tests/dst')
    spec = KittenGroomerFileCheck(src, dst, debug=True)
    spec.processdir()
    self.dump_logs(spec)

## Helper functions

def dump_logs(self, kg):
    print(open(kg.log_processing, 'rb').read())
    if kg.debug:
        if os.path.exists(kg.log_debug_err):
            print(open(kg.log_debug_err, 'rb').read())
        if os.path.exists(kg.log_debug_out):
            print(open(kg.log_debug_out, 'rb').read())
